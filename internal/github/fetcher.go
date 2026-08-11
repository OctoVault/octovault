package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	ovmetrics "github.com/octovault/octovault/internal/metrics"
)

// maxErrorBodyBytes 오류 응답에서 읽어들일 최대 바이트.
// 바디를 끝까지 읽지 않으면 Go transport 가 커넥션을 재사용하지 않으므로
// 오류 경로에서도 반드시 드레인해야 한다.
const maxErrorBodyBytes = 4 << 10

type Options struct {
	BaseURL    string       // e.g. "https://api.github.com"
	HTTPClient *http.Client // nil = default client

	// SchemaFileName 비우면 스키마를 아예 조회하지 않는다.
	// Validator 가 설정되지 않은 배포에서는 반드시 비워야 한다. 그렇지 않으면
	// 쓰이지도 않는 파일 때문에 폴링마다 요청 1개를 낭비한다.
	SchemaFileName string

	Ref       string // default ref (fallback when per-call ref is empty)
	UserAgent string // default: "octovault-operator"

	// RevisionFromCommit true 면 revision 을 얻기 위해 /commits 를 추가 조회한다.
	// false(기본)면 contents 응답에 이미 들어있는 blob SHA 를 쓴다. blob SHA 는
	// 파일 내용이 바뀔 때만 변하므로 revision 마커로 충분하며 요청 1개를 아낀다.
	RevisionFromCommit bool

	// CacheEntries ETag 캐시 크기. 0 이면 DefaultCacheEntries.
	CacheEntries int

	// DisableConditionalRequests true 면 If-None-Match 를 보내지 않는다. 디버깅용.
	DisableConditionalRequests bool

	// Now 테스트 주입용. nil 이면 time.Now.
	Now func() time.Time
}

type Fetcher struct {
	baseURL            string
	httpClient         *http.Client
	schemaFileName     string
	ref                string
	userAgent          string
	revisionFromCommit bool
	conditional        bool
	cache              *lru[etagEntry]
	now                func() time.Time
}

// etagEntry 조건부 요청에 필요한 ETag 와, 304 응답 시 되돌려줄 원본 바디.
//
// GitHub 는 If-None-Match 로 304 를 받은 요청을 primary rate limit 에 카운트하지 않는다.
// 따라서 내용이 바뀌지 않는 한 폴링 비용이 0 이 된다.
type etagEntry struct {
	etag string
	body []byte
}

func NewFetcher(opts Options) *Fetcher {

	base := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if base == "" {

		base = "https://api.github.com"
	}

	hc := opts.HTTPClient
	if hc == nil {

		hc = &http.Client{Timeout: 15 * time.Second}
	}

	ua := opts.UserAgent
	if ua == "" {

		ua = "octovault-operator"
	}

	nowFn := opts.Now
	if nowFn == nil {

		nowFn = time.Now
	}

	return &Fetcher{
		baseURL:            base,
		httpClient:         hc,
		schemaFileName:     strings.TrimSpace(opts.SchemaFileName),
		ref:                strings.TrimSpace(opts.Ref),
		userAgent:          ua,
		revisionFromCommit: opts.RevisionFromCommit,
		conditional:        !opts.DisableConditionalRequests,
		cache:              newLRU[etagEntry](opts.CacheEntries),
		now:                nowFn,
	}
}

// 컨트롤러 인터페이스 준수
var _ interface {
	Fetch(context.Context, string, string, string, string, string) ([]byte, []byte, string, error)
} = (*Fetcher)(nil)

func (f *Fetcher) Fetch(ctx context.Context, org, repo, filePath, ref, token string) ([]byte, []byte, string, error) {

	owner := strings.TrimPrefix(strings.TrimSpace(org), "github.com/")
	if owner == "" {

		return nil, nil, "", errors.New("invalid org: expected 'github.com/<org>'")
	}

	repoName := lastSegment(repo)
	fp := strings.TrimPrefix(filePath, "/")

	// per-call ref > default ref
	refParam := strings.TrimSpace(ref)
	if refParam == "" {

		refParam = f.ref
	}

	// 1) values.yaml
	contentURL := f.contentURL(owner, repoName, fp, refParam)

	values, blobSHA, err := f.fetchContentBase64(ctx, contentRequest{url: contentURL, token: token, kind: "contents"})
	if err != nil {

		return nil, nil, "", fmt.Errorf("fetch values.yaml failed: %w", err)
	}

	// 2) schema (optional) — SchemaFileName 이 비어있으면 요청을 보내지 않는다.
	var schema []byte
	if f.schemaFileName != "" {

		schemaPath := path.Join(dirOf(fp), f.schemaFileName)
		schemaURL := f.contentURL(owner, repoName, schemaPath, refParam)

		if s, _, sErr := f.fetchContentBase64(ctx, contentRequest{url: schemaURL, token: token, kind: "schema"}); sErr == nil {

			schema = s
		}
	}

	// 3) revision — 기본은 blob SHA. RevisionFromCommit 일 때만 커밋을 추가 조회한다.
	rev := blobSHA
	if f.revisionFromCommit {
		if sha, cErr := f.fetchLatestCommitSHA(ctx, commitRequest{
			owner: owner,
			repo:  repoName,
			path:  fp,
			ref:   refParam,
			token: token,
		}); cErr == nil && sha != "" {

			rev = sha
		}
	}

	return values, schema, rev, nil
}

func (f *Fetcher) contentURL(owner, repo, fp, refParam string) string {

	u := f.apiURL(fmt.Sprintf("/repos/%s/%s/contents/%s",
		url.PathEscape(owner), url.PathEscape(repo), escapePath(fp)))

	if refParam != "" {

		u += "?ref=" + url.QueryEscape(refParam)
	}

	return u
}

type contentRequest struct {
	url   string
	token string
	kind  string
}

func (f *Fetcher) fetchContentBase64(ctx context.Context, cr contentRequest) ([]byte, string, error) {

	body, err := f.doJSON(ctx, cr)
	if err != nil {

		return nil, "", err
	}

	var c contentResp
	if err := json.Unmarshal(body, &c); err != nil {

		return nil, "", err
	}

	if strings.ToLower(strings.TrimSpace(c.Encoding)) != "base64" {

		return nil, "", fmt.Errorf("unsupported encoding %q", c.Encoding)
	}

	raw := strings.ReplaceAll(c.Content, "\n", "")

	out, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {

		return nil, "", fmt.Errorf("base64 decode: %w", err)
	}

	return out, c.SHA, nil
}

type commitRequest struct {
	owner string
	repo  string
	path  string
	ref   string
	token string
}

func (f *Fetcher) fetchLatestCommitSHA(ctx context.Context, cr commitRequest) (string, error) {

	u := f.apiURL(fmt.Sprintf("/repos/%s/%s/commits", url.PathEscape(cr.owner), url.PathEscape(cr.repo)))

	v := url.Values{}
	v.Set("path", cr.path)
	v.Set("per_page", "1")

	if strings.TrimSpace(cr.ref) != "" {

		v.Set("sha", cr.ref) // branch/tag/SHA pin
	}

	u += "?" + v.Encode()

	body, err := f.doJSON(ctx, contentRequest{url: u, token: cr.token, kind: "commits"})
	if err != nil {

		return "", err
	}

	var commits []commitResp
	if err := json.Unmarshal(body, &commits); err != nil {

		return "", err
	}

	if len(commits) > 0 && commits[0].SHA != "" {

		return commits[0].SHA, nil
	}

	return "", nil
}

// doJSON 조건부 요청과 rate limit 관측을 담당하는 단일 진입점.
// 200 이면 바디를 ETag 와 함께 캐시하고, 304 면 캐시된 바디를 되돌려준다.
func (f *Fetcher) doJSON(ctx context.Context, cr contentRequest) ([]byte, error) {

	key := credentialScopedKey(cr.url, cr.token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cr.url, nil)
	if err != nil {

		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cr.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", f.userAgent)

	cached, hasCached := f.cache.get(key)
	if f.conditional && hasCached {

		req.Header.Set("If-None-Match", cached.etag)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {

		return nil, err
	}
	defer func() {
		// 커넥션 재사용을 위해 남은 바디를 버린다.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
		_ = resp.Body.Close()
	}()

	observeRateLimit(cr.kind, cr.token, resp)

	switch resp.StatusCode {
	case http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {

			return nil, err
		}

		if etag := strings.TrimSpace(resp.Header.Get("ETag")); etag != "" {

			f.cache.put(key, etagEntry{etag: etag, body: body})
		}

		return body, nil

	case http.StatusNotModified:
		ovmetrics.ConditionalHitsTotal.WithLabelValues(cr.kind).Inc()

		if hasCached && len(cached.body) > 0 {

			return cached.body, nil
		}

		// ETag 는 보냈지만 되돌려줄 바디가 없는 상태. 캐시를 버리고 다음 폴링에서 200 을 받는다.
		f.cache.drop(key)

		return nil, errors.New("304 not modified but no cached body available")

	case http.StatusNotFound:
		return nil, fmt.Errorf("404 not found: %s", cr.url)

	case http.StatusUnauthorized:
		return nil, errors.New("401 unauthorized")

	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, f.limitOrPermissionError(cr.kind, resp)

	default:
		return nil, fmt.Errorf("%d unexpected", resp.StatusCode)
	}
}

// limitOrPermissionError 403/429 를 rate limit 과 권한 오류로 구분해 반환한다.
func (f *Fetcher) limitOrPermissionError(kind string, resp *http.Response) error {

	peek, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))

	if rle, limited := rateLimitErrorFrom(kind, resp, peek, f.now()); limited {

		return rle
	}

	if resp.StatusCode == http.StatusForbidden {

		return errors.New("403 forbidden: token lacks access to the resource")
	}

	return fmt.Errorf("%d unexpected", resp.StatusCode)
}

func (f *Fetcher) apiURL(p string) string {

	return strings.TrimRight(f.baseURL, "/") + p
}

func dirOf(fp string) string {

	dir := path.Dir("/" + fp)
	if dir == "/" || dir == "." {

		return ""
	}

	return strings.TrimPrefix(dir, "/")
}

func lastSegment(s string) string {

	s = strings.Trim(s, "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {

		return s[i+1:]
	}

	return s
}

func escapePath(pth string) string {

	pth = strings.TrimPrefix(pth, "/")
	if pth == "" {

		return ""
	}

	parts := strings.Split(pth, "/")
	for i := range parts {

		parts[i] = url.PathEscape(parts[i])
	}

	return strings.Join(parts, "/")
}

// payloads
type contentResp struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	SHA      string `json:"sha"`
}

type commitResp struct {
	SHA string `json:"sha"`
}
