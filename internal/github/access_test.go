package github

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestChecker(t *testing.T, stub *stubRT, now *time.Time) *AccessChecker {
	t.Helper()

	return NewAccessChecker(AccessOptions{
		BaseURL:    "https://api.github.com",
		HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: stub},
		TTL:        10 * time.Minute,
		Now:        func() time.Time { return *now },
	})
}

// TTL 안에서는 몇 번 호출하든 GitHub 요청이 1회만 나가야 한다.
// 이게 fan-out 이 rate limit 을 소모하지 않게 하는 핵심이다.
func TestAccessChecker_CachesSuccessWithinTTL(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/orgs/acme/repos") {

			return jsonResp(http.StatusOK, []any{}), nil
		}

		return jsonResp(http.StatusNotFound, nil), nil
	}

	c := newTestChecker(t, stub, &now)

	for range 5 {
		require.NoError(t, c.Check(ctx, "github.com/acme", "tok"))
	}

	require.Len(t, stub.requests, 1, "TTL 안에서는 프로브가 1회만 나가야 한다")
}

// TTL 이 지나면 다시 프로브한다.
func TestAccessChecker_ReprobesAfterTTL(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {

		return jsonResp(http.StatusOK, []any{}), nil
	}

	c := newTestChecker(t, stub, &now)

	require.NoError(t, c.Check(ctx, "github.com/acme", "tok"))
	require.Len(t, stub.requests, 1)

	now = now.Add(11 * time.Minute)
	require.NoError(t, c.Check(ctx, "github.com/acme", "tok"))
	require.Len(t, stub.requests, 2)
}

// 토큰이 바뀌면 캐시 키가 바뀌므로 TTL 을 기다리지 않고 즉시 재검증된다.
// 잘못된 토큰을 고친 사용자가 TTL 만큼 기다리지 않아도 되게 하는 성질이다.
func TestAccessChecker_TokenChangeInvalidatesCache(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "Bearer good" {

			return jsonResp(http.StatusOK, []any{}), nil
		}

		return jsonResp(http.StatusUnauthorized, nil), nil
	}

	c := newTestChecker(t, stub, &now)

	require.Error(t, c.Check(ctx, "github.com/acme", "bad"))
	require.NoError(t, c.Check(ctx, "github.com/acme", "good"),
		"토큰을 고치면 TTL 을 기다리지 않고 재검증돼야 한다")
}

// 개인 계정이면 org 프로브가 404 → user 프로브로 폴백하고,
// 그 사실을 기억해서 다음 재검증에서는 요청 1개만 쓴다.
func TestAccessChecker_RemembersUserAccountToSaveARequest(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/users/eugene/repos") {

			return jsonResp(http.StatusOK, []any{}), nil
		}

		return jsonResp(http.StatusNotFound, nil), nil
	}

	c := newTestChecker(t, stub, &now)

	require.NoError(t, c.Check(ctx, "github.com/eugene", "tok"))
	require.Equal(t, 2, len(stub.requests), "첫 검증은 org 프로브 실패 후 user 프로브로 폴백한다")

	now = now.Add(11 * time.Minute)
	require.NoError(t, c.Check(ctx, "github.com/eugene", "tok"))
	require.Equal(t, 3, len(stub.requests), "두 번째 검증은 user 프로브만 써야 한다")
	require.Contains(t, stub.requests[2].URL.Path, "/users/eugene/repos")
}

// rate limit 이면 user 프로브 폴백을 시도하지 않는다. 같은 이유로 거절되고 한도만 더 쓴다.
func TestAccessChecker_RateLimit_SkipsUserFallback(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	reset := now.Add(9 * time.Minute)

	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
		resp.Header.Set("X-RateLimit-Remaining", "0")
		resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

		return resp, nil
	}

	c := newTestChecker(t, stub, &now)

	err := c.Check(ctx, "github.com/acme", "tok")
	require.Error(t, err)
	require.Len(t, stub.requests, 1, "rate limit 이면 폴백 프로브를 보내지 않아야 한다")

	retryAfter, limited := RetryAfterFor(err)
	require.True(t, limited)
	require.Equal(t, 9*time.Minute, retryAfter)
}

// rate limit 결과는 리셋 시각까지 캐시해 재시도를 막는다.
func TestAccessChecker_CachesRateLimitUntilReset(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	reset := now.Add(9 * time.Minute)

	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusForbidden, nil)
		resp.Header.Set("X-RateLimit-Remaining", "0")
		resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))

		return resp, nil
	}

	c := newTestChecker(t, stub, &now)

	require.Error(t, c.Check(ctx, "github.com/acme", "tok"))
	require.Len(t, stub.requests, 1)

	// 리셋 전에는 다시 찔러보지 않는다
	now = now.Add(5 * time.Minute)
	require.Error(t, c.Check(ctx, "github.com/acme", "tok"))
	require.Len(t, stub.requests, 1, "리셋 전에는 프로브를 재시도하지 않아야 한다")

	// 리셋 후에는 다시 시도한다
	now = now.Add(5 * time.Minute)
	require.Error(t, c.Check(ctx, "github.com/acme", "tok"))
	require.Greater(t, len(stub.requests), 1)
}

// 실패도 캐시한다. 잘못된 토큰이 매 reconcile 마다 API 를 낭비하지 않게 한다.
func TestAccessChecker_CachesFailureWithinNegativeTTL(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {

		return jsonResp(http.StatusNotFound, nil), nil
	}

	c := NewAccessChecker(AccessOptions{
		BaseURL:     "https://api.github.com",
		HTTPClient:  &http.Client{Timeout: 5 * time.Second, Transport: stub},
		TTL:         10 * time.Minute,
		NegativeTTL: 5 * time.Minute,
		Now:         func() time.Time { return now },
	})

	require.Error(t, c.Check(ctx, "github.com/nope", "tok"))
	before := len(stub.requests)

	now = now.Add(2 * time.Minute)
	require.Error(t, c.Check(ctx, "github.com/nope", "tok"))
	require.Equal(t, before, len(stub.requests), "negative TTL 안에서는 재프로브하지 않아야 한다")
}

func TestAccessChecker_RejectsEmptyOwner(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {

		t.Fatal("요청이 발생해서는 안 된다")
		return nil, nil
	}

	c := newTestChecker(t, stub, &now)

	require.Error(t, c.Check(ctx, "github.com/", "tok"))
	require.Empty(t, stub.requests)
}
