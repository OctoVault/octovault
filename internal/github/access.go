package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ovmetrics "github.com/octovault/octovault/internal/metrics"
)

const (
	// DefaultAccessTTL 성공한 자격증명 검증을 신뢰하는 기간
	DefaultAccessTTL = 10 * time.Minute

	// DefaultAccessNegativeTTL 실패한 검증을 캐시하는 기간.
	//
	// 캐시 키에 토큰 지문이 들어가므로 토큰을 고쳐 넣으면 즉시 재검증된다.
	// 따라서 이 값은 "같은 토큰인데 조직 쪽 권한이 바뀐 경우"만 커버하면 되고,
	// 짧게 잡을 이유가 없다. 짧으면 잘못된 토큰이 계속 API 를 낭비한다.
	DefaultAccessNegativeTTL = 5 * time.Minute

	probeTimeout = 10 * time.Second
)

type AccessOptions struct {
	BaseURL      string
	HTTPClient   *http.Client
	UserAgent    string
	TTL          time.Duration
	NegativeTTL  time.Duration
	CacheEntries int
	Now          func() time.Time
}

// AccessChecker 조직/사용자 접근 권한 검증기.
//
// 검증 결과를 TTL 동안 캐시하므로, reconcile 이 몇 번 돌든 TTL 안에서는
// GitHub 요청이 발생하지 않는다. OctoRepository 가 watch/fan-out 으로
// 자주 깨어나도 rate limit 을 소모하지 않게 하는 것이 목적이다.
type AccessChecker struct {
	baseURL     string
	httpClient  *http.Client
	userAgent   string
	ttl         time.Duration
	negativeTTL time.Duration
	cache       *lru[accessEntry]
	now         func() time.Time
}

// AccessResult 검증 성공 시 함께 알 수 있는 정보.
type AccessResult struct {
	// LimitedToPublic 클래식 PAT 의 X-OAuth-Scopes 에 "repo" 가 없어 public 저장소만 읽을 수 있다.
	// fine-grained PAT 나 GitHub App 토큰은 이 헤더를 보내지 않으므로 항상 false 다.
	LimitedToPublic bool
}

type accessEntry struct {
	err       error
	result    AccessResult
	expiresAt time.Time

	// preferUser 이 owner 가 조직이 아니라 개인 계정으로 확인된 경우 true.
	// 다음 검증에서 조직 프로브를 건너뛰어 요청 1개를 아낀다.
	preferUser bool
}

func NewAccessChecker(opts AccessOptions) *AccessChecker {

	base := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if base == "" {

		base = "https://api.github.com"
	}

	hc := opts.HTTPClient
	if hc == nil {

		hc = &http.Client{Timeout: probeTimeout}
	}

	ua := opts.UserAgent
	if ua == "" {

		ua = "octovault-operator"
	}

	ttl := opts.TTL
	if ttl <= 0 {

		ttl = DefaultAccessTTL
	}

	negTTL := opts.NegativeTTL
	if negTTL <= 0 {

		negTTL = DefaultAccessNegativeTTL
	}

	nowFn := opts.Now
	if nowFn == nil {

		nowFn = time.Now
	}

	return &AccessChecker{
		baseURL:     base,
		httpClient:  hc,
		userAgent:   ua,
		ttl:         ttl,
		negativeTTL: negTTL,
		cache:       newLRU[accessEntry](opts.CacheEntries),
		now:         nowFn,
	}
}

// Check 접근 가능 여부만 필요한 호출자를 위한 래퍼.
func (a *AccessChecker) Check(ctx context.Context, org, token string) error {

	_, err := a.CheckAccess(ctx, org, token)

	return err
}

// CheckAccess controller.OrgAccessChecker 를 만족한다.
func (a *AccessChecker) CheckAccess(ctx context.Context, org, token string) (AccessResult, error) {

	owner := strings.TrimPrefix(strings.TrimSpace(org), "github.com/")
	if owner == "" {

		return AccessResult{}, fmt.Errorf("invalid owner: expected 'github.com/<owner>', got %q", org)
	}

	key := credentialScopedKey(owner, token)
	now := a.now()

	prev, hadPrev := a.cache.get(key)
	if hadPrev && now.Before(prev.expiresAt) {

		ovmetrics.CredentialCheckCacheTotal.WithLabelValues("hit").Inc()

		return prev.result, prev.err
	}

	ovmetrics.CredentialCheckCacheTotal.WithLabelValues("miss").Inc()

	outcome, err := a.probe(ctx, probeTarget{
		owner:      owner,
		token:      token,
		preferUser: hadPrev && prev.preferUser,
	})

	result := AccessResult{LimitedToPublic: outcome.limitedToPublic}
	a.cache.put(key, accessEntry{
		err:        err,
		result:     result,
		expiresAt:  now.Add(a.cacheTTLFor(err)),
		preferUser: outcome.preferUser,
	})

	return result, err
}

type probeTarget struct {
	owner      string
	token      string
	preferUser bool
}

type probeOutcome struct {
	preferUser      bool // owner 가 개인 계정으로 판별됨
	limitedToPublic bool
}

// probe 접근 가능 여부를 실제로 확인한다.
func (a *AccessChecker) probe(ctx context.Context, target probeTarget) (probeOutcome, error) {

	orgProbe := probeSpec{
		url:     fmt.Sprintf("%s/orgs/%s/repos?per_page=1", a.baseURL, target.owner),
		kind:    "org-probe",
		subject: "organization",
		owner:   target.owner,
		token:   target.token,
	}
	userProbe := probeSpec{
		url:     fmt.Sprintf("%s/users/%s/repos?per_page=1", a.baseURL, target.owner),
		kind:    "user-probe",
		subject: "user",
		owner:   target.owner,
		token:   target.token,
	}

	if target.preferUser {
		if limited, err := a.probeList(ctx, userProbe); err == nil {

			return probeOutcome{preferUser: true, limitedToPublic: limited}, nil
		}
	}

	limited, orgErr := a.probeList(ctx, orgProbe)
	if orgErr == nil {

		return probeOutcome{limitedToPublic: limited}, nil
	}

	// rate limit 이면 개인 계정 폴백을 시도하지 않는다. 어차피 같은 이유로 거절되고
	// 한도만 더 소모한다.
	if _, rateLimited := AsRateLimitError(orgErr); rateLimited {

		return probeOutcome{preferUser: target.preferUser}, orgErr
	}

	limited, userErr := a.probeList(ctx, userProbe)
	if userErr == nil {

		return probeOutcome{preferUser: true, limitedToPublic: limited}, nil
	}

	return probeOutcome{preferUser: target.preferUser}, fmt.Errorf("org probe failed: %v; user probe failed: %v", orgErr, userErr)
}

// cacheTTLFor rate limit 이면 리셋 시점까지 캐시해 재시도를 막는다.
func (a *AccessChecker) cacheTTLFor(err error) time.Duration {
	if err == nil {

		return a.ttl
	}

	if rle, ok := AsRateLimitError(err); ok {

		return rle.RetryAfter
	}

	return a.negativeTTL
}

type probeSpec struct {
	url     string
	kind    string
	subject string
	owner   string
	token   string
}

// probeList 성공하면 토큰이 public 저장소로 제한되는지 함께 반환한다.
func (a *AccessChecker) probeList(ctx context.Context, spec probeSpec) (bool, error) {

	cctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, spec.url, nil)
	if err != nil {

		return false, err
	}

	req.Header.Set("Authorization", "Bearer "+spec.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", a.userAgent)

	resp, err := a.httpClient.Do(req)
	if err != nil {

		return false, err
	}
	defer func() {
		// 커넥션 재사용을 위해 바디를 드레인한다.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
		_ = resp.Body.Close()
	}()

	observeRateLimit(spec.kind, spec.token, resp)

	switch resp.StatusCode {
	case http.StatusOK:
		return limitedToPublic(resp.Header), nil

	case http.StatusUnauthorized:
		return false, errors.New("401 unauthorized: invalid token or scope")

	case http.StatusForbidden, http.StatusTooManyRequests:
		peek, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))

		if rle, limited := rateLimitErrorFrom(spec.kind, resp, peek, a.now()); limited {

			return false, rle
		}

		return false, errors.New("403 forbidden: token lacks access to the resource")

	case http.StatusNotFound:
		return false, fmt.Errorf("404 not found: no access to the %s %q or it does not exist", spec.subject, spec.owner)

	default:
		return false, fmt.Errorf("%d unexpected: cannot verify %s %q", resp.StatusCode, spec.subject, spec.owner)
	}
}

// limitedToPublic 클래식 PAT/OAuth 토큰은 X-OAuth-Scopes 로 스코프를 알려준다.
// 스코프 목록이 있는데 "repo" 가 없으면 private 저장소를 읽을 수 없다.
//
// 헤더가 없거나 비어 있으면 판단하지 않는다. fine-grained PAT 와 GitHub App 토큰은 스코프 대신
// 저장소별 권한을 쓰므로 이 헤더가 의미가 없고, 빈 값으로 오는지 아예 빠지는지가 문서로 보장되지
// 않는다. 그 토큰들을 잘못 경고하느니, 스코프가 하나도 없는 클래식 PAT 를 놓치는 쪽을 택한다.
func limitedToPublic(h http.Header) bool {

	scopes := strings.TrimSpace(h.Get("X-OAuth-Scopes"))
	if scopes == "" {

		return false
	}

	for _, scope := range strings.Split(scopes, ",") {
		if strings.TrimSpace(scope) == "repo" {

			return false
		}
	}

	return true
}
