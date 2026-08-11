package github

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	ovmetrics "github.com/octovault/octovault/internal/metrics"
)

const (
	// MinRateLimitBackoff 리셋 시각이 이미 지난 것으로 계산될 때의 하한
	MinRateLimitBackoff = 5 * time.Second

	// MaxRateLimitBackoff GitHub가 비정상적으로 먼 리셋 시각을 주더라도 이 이상은 기다리지 않는다
	MaxRateLimitBackoff = time.Hour

	// FallbackRateLimitBackoff 헤더가 전혀 없을 때 사용
	FallbackRateLimitBackoff = time.Minute
)

// LimitKind primary(시간당 할당량) 와 secondary(순간 버스트 제한) 를 구분한다.
// 원인 진단과 백오프 전략이 서로 다르기 때문에 뭉뚱그리지 않는다.
type LimitKind string

const (
	LimitPrimary   LimitKind = "primary"
	LimitSecondary LimitKind = "secondary"
)

// RateLimit 응답 헤더에서 읽은 사용량 스냅샷
type RateLimit struct {
	Resource   string
	Limit      int
	Remaining  int
	Reset      time.Time
	Credential string
	Known      bool
}

// RateLimitError rate limit 으로 거절된 요청. 호출자는 RetryAfter 만큼 기다려야 한다.
type RateLimitError struct {
	StatusCode int
	Kind       LimitKind
	Snapshot   RateLimit
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	if e.Snapshot.Known {

		return fmt.Sprintf("%d %s rate limit exhausted (resource=%s limit=%d remaining=%d); retry after %s",
			e.StatusCode, e.Kind, e.Snapshot.Resource, e.Snapshot.Limit, e.Snapshot.Remaining, e.RetryAfter)
	}

	return fmt.Sprintf("%d %s rate limit exhausted; retry after %s", e.StatusCode, e.Kind, e.RetryAfter)
}

// AsRateLimitError 에러 체인에서 RateLimitError 를 꺼낸다.
func AsRateLimitError(err error) (*RateLimitError, bool) {
	var rle *RateLimitError
	if errors.As(err, &rle) {

		return rle, true
	}

	return nil, false
}

// RetryAfterFor rate limit 에러라면 권장 대기 시간을 반환한다.
func RetryAfterFor(err error) (time.Duration, bool) {
	if rle, ok := AsRateLimitError(err); ok {

		return rle.RetryAfter, true
	}

	return 0, false
}

// parseRateLimit X-RateLimit-* 헤더를 해석한다.
func parseRateLimit(h http.Header) RateLimit {

	out := RateLimit{Resource: strings.TrimSpace(h.Get("X-RateLimit-Resource"))}
	if out.Resource == "" {

		out.Resource = "core"
	}

	remaining := strings.TrimSpace(h.Get("X-RateLimit-Remaining"))
	if remaining == "" {

		return out
	}

	n, err := strconv.Atoi(remaining)
	if err != nil {

		return out
	}

	out.Remaining = n
	out.Known = true

	if v, err := strconv.Atoi(strings.TrimSpace(h.Get("X-RateLimit-Limit"))); err == nil {

		out.Limit = v
	}

	if v, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && v > 0 {

		out.Reset = time.Unix(v, 0)
	}

	return out
}

// retryAfterFrom Retry-After(초) 헤더가 우선이고, 없으면 리셋 시각까지의 잔여 시간을 쓴다.
func retryAfterFrom(h http.Header, snap RateLimit, now time.Time) time.Duration {
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {

			return clampBackoff(time.Duration(secs) * time.Second)
		}
	}

	if !snap.Reset.IsZero() {

		return clampBackoff(snap.Reset.Sub(now))
	}

	return FallbackRateLimitBackoff
}

func clampBackoff(d time.Duration) time.Duration {
	if d < MinRateLimitBackoff {

		return MinRateLimitBackoff
	}

	if d > MaxRateLimitBackoff {

		return MaxRateLimitBackoff
	}

	return d
}

// isRateLimited 403/429 가 권한 문제인지 rate limit 인지 판별한다.
// 403 은 둘 다에 쓰이므로 remaining==0 또는 secondary 안내 문구로 구분해야 한다.
func isRateLimited(status int, h http.Header, snap RateLimit, body []byte) (LimitKind, bool) {
	if status == http.StatusTooManyRequests {
		if snap.Known && snap.Remaining == 0 {

			return LimitPrimary, true
		}

		return LimitSecondary, true
	}

	if status != http.StatusForbidden {

		return "", false
	}

	if snap.Known && snap.Remaining == 0 {

		return LimitPrimary, true
	}

	if strings.TrimSpace(h.Get("Retry-After")) != "" {

		return LimitSecondary, true
	}

	if strings.Contains(strings.ToLower(string(body)), "secondary rate limit") {

		return LimitSecondary, true
	}

	return "", false
}

// observeRateLimit 모든 응답에서 사용량 헤더를 메트릭으로 내보낸다.
// Fetcher 와 AccessChecker 가 공유한다.
func observeRateLimit(kind, token string, resp *http.Response) {

	ovmetrics.RequestsTotal.WithLabelValues(kind, strconv.Itoa(resp.StatusCode)).Inc()

	snap := parseRateLimit(resp.Header)
	if !snap.Known {

		return
	}

	cred := credentialLabel(token)
	ovmetrics.RateLimitRemaining.WithLabelValues(snap.Resource, cred).Set(float64(snap.Remaining))

	if snap.Limit > 0 {

		ovmetrics.RateLimitTotal.WithLabelValues(snap.Resource, cred).Set(float64(snap.Limit))
	}

	if !snap.Reset.IsZero() {

		ovmetrics.RateLimitResetSeconds.WithLabelValues(snap.Resource, cred).Set(float64(snap.Reset.Unix()))
	}
}

// rateLimitErrorFrom 403/429 응답을 rate limit 에러로 변환한다.
// rate limit 이 아니면 (nil, false) 를 반환한다. 호출 전에 바디를 peek 해서 넘겨야 한다.
func rateLimitErrorFrom(kind string, resp *http.Response, body []byte, now time.Time) (*RateLimitError, bool) {

	snap := parseRateLimit(resp.Header)

	limitKind, limited := isRateLimited(resp.StatusCode, resp.Header, snap, body)
	if !limited {

		return nil, false
	}

	ovmetrics.RateLimitedTotal.WithLabelValues(kind).Inc()

	return &RateLimitError{
		StatusCode: resp.StatusCode,
		Kind:       limitKind,
		Snapshot:   snap,
		RetryAfter: retryAfterFrom(resp.Header, snap, now),
	}, true
}

// credentialLabel 토큰을 메트릭 라벨로 쓰기 위한 비가역 지문.
// 원문 토큰은 절대 라벨/로그에 노출하지 않는다.
func credentialLabel(token string) string {
	if strings.TrimSpace(token) == "" {

		return "anonymous"
	}

	sum := sha256.Sum256([]byte(token))

	return hex.EncodeToString(sum[:4])
}
