package github

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func countPaths(reqs []*http.Request) map[string]int {

	out := map[string]int{}
	for _, r := range reqs {
		switch {
		case strings.Contains(r.URL.Path, "/commits"):
			out["commits"]++
		case strings.Contains(r.URL.Path, "validator.schema.json"):
			out["schema"]++
		case strings.Contains(r.URL.Path, "/contents/"):
			out["contents"]++
		default:
			out["other"]++
		}
	}

	return out
}

// 기본 설정에서는 요청이 contents 1개뿐이어야 한다.
// 스키마 조회와 커밋 조회는 각각 옵트인이다.
func TestFetcher_DefaultIssuesSingleRequest(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}

	// SchemaFileName 을 비우고 RevisionFromCommit 도 끈 기본 구성
	f := NewFetcher(Options{HTTPClient: client, Ref: "main"})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/contents/values.yaml") {

			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  b64WithNewline("a: 1\n"),
				SHA:      "blob-abc",
			}), nil
		}

		return jsonResp(http.StatusNotFound, nil), nil
	}

	values, schema, rev, err := f.Fetch(ctx, "github.com/org", "repo", "values.yaml", "", "tok")
	require.NoError(t, err)
	require.Equal(t, []byte("a: 1\n"), values)
	require.Nil(t, schema)
	require.Equal(t, "blob-abc", rev, "revision 은 contents 응답의 blob SHA 를 써야 한다")

	require.Len(t, stub.requests, 1, "기본 구성에서 GitHub 요청은 1개여야 한다")
	require.Equal(t, map[string]int{"contents": 1}, countPaths(stub.requests))
}

// SchemaFileName 이 비어있으면 스키마 요청을 아예 보내지 않아야 한다.
// (404 도 rate limit 에 카운트되므로 "실패해도 무해"하지 않다)
func TestFetcher_NoSchemaRequestWhenSchemaFileNameEmpty(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client, SchemaFileName: ""})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "validator.schema.json") {

			t.Fatalf("schema 요청이 발생했다: %s", r.URL)
		}

		return jsonResp(http.StatusOK, contentResp{
			Encoding: "base64",
			Content:  b64WithNewline("x: y\n"),
			SHA:      "b1",
		}), nil
	}

	_, schema, _, err := f.Fetch(ctx, "github.com/o", "r", "app/values.yaml", "", "tok")
	require.NoError(t, err)
	require.Nil(t, schema)
	require.Equal(t, 0, countPaths(stub.requests)["schema"])
}

// 두 번째 폴링은 If-None-Match 를 보내고, 304 를 받으면 캐시된 내용을 반환해야 한다.
func TestFetcher_ConditionalRequest_ReusesCacheOn304(t *testing.T) {
	ctx := context.Background()

	const etag = `W/"deadbeef"`

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	calls := 0
	stub.handler = func(r *http.Request) (*http.Response, error) {

		calls++
		if calls == 1 {

			require.Empty(t, r.Header.Get("If-None-Match"), "첫 요청에는 보낼 ETag 가 없다")

			resp := jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  b64WithNewline("k: v\n"),
				SHA:      "blob-1",
			})
			resp.Header.Set("ETag", etag)

			return resp, nil
		}

		require.Equal(t, etag, r.Header.Get("If-None-Match"), "두 번째 요청은 조건부여야 한다")

		resp := jsonResp(http.StatusNotModified, nil)
		resp.Header.Set("ETag", etag)

		return resp, nil
	}

	v1, _, rev1, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.NoError(t, err)

	v2, _, rev2, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.NoError(t, err)

	require.Equal(t, v1, v2, "304 응답에서도 같은 내용을 반환해야 한다")
	require.Equal(t, rev1, rev2)
	require.Equal(t, 2, calls)
}

// 캐시 키에 토큰 지문이 들어가므로, 토큰이 바뀌면 조건부 요청을 보내지 않는다.
func TestFetcher_CacheIsScopedPerCredential(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusOK, contentResp{
			Encoding: "base64",
			Content:  b64WithNewline("k: v\n"),
			SHA:      "blob-1",
		})
		resp.Header.Set("ETag", `"tag"`)

		return resp, nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "token-a")
	require.NoError(t, err)

	_, _, _, err = f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "token-b")
	require.NoError(t, err)

	require.Len(t, stub.requests, 2)
	require.Empty(t, stub.requests[1].Header.Get("If-None-Match"),
		"다른 토큰의 요청에 이전 토큰의 ETag 를 재사용해서는 안 된다")
}

// primary rate limit 소진(403 + remaining=0) 은 권한 오류가 아니라
// RateLimitError 로 분류되고, 리셋 시각까지의 대기 시간을 담아야 한다.
func TestFetcher_PrimaryRateLimit_IsTypedError(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	reset := now.Add(12 * time.Minute)

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{
		HTTPClient: client,
		Now:        func() time.Time { return now },
	})

	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
		resp.Header.Set("X-RateLimit-Limit", "5000")
		resp.Header.Set("X-RateLimit-Remaining", "0")
		resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		resp.Header.Set("X-RateLimit-Resource", "core")

		return resp, nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.Error(t, err)

	retryAfter, limited := RetryAfterFor(err)
	require.True(t, limited, "403 + remaining=0 은 rate limit 으로 분류해야 한다")
	require.Equal(t, 12*time.Minute, retryAfter)

	rle, ok := AsRateLimitError(err)
	require.True(t, ok)
	require.Equal(t, LimitPrimary, rle.Kind)
	require.Equal(t, 5000, rle.Snapshot.Limit)
	require.Equal(t, "core", rle.Snapshot.Resource)
}

// secondary rate limit 은 Retry-After 를 따른다.
func TestFetcher_SecondaryRateLimit_UsesRetryAfter(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client, Now: func() time.Time { return now }})

	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusForbidden, map[string]string{
			"message": "You have exceeded a secondary rate limit",
		})
		resp.Header.Set("Retry-After", "45")
		resp.Header.Set("X-RateLimit-Remaining", "4321")

		return resp, nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.Error(t, err)

	rle, ok := AsRateLimitError(err)
	require.True(t, ok)
	require.Equal(t, LimitSecondary, rle.Kind)
	require.Equal(t, 45*time.Second, rle.RetryAfter)
}

// remaining 이 남아있는 403 은 rate limit 이 아니라 권한 문제로 남겨야 한다.
// 이걸 rate limit 으로 오분류하면 잘못된 토큰을 한 시간씩 기다리게 된다.
func TestFetcher_Forbidden_WithQuotaLeft_IsNotRateLimit(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusForbidden, map[string]string{"message": "Resource not accessible"})
		resp.Header.Set("X-RateLimit-Remaining", "4999")
		resp.Header.Set("X-RateLimit-Limit", "5000")

		return resp, nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.Error(t, err)

	_, limited := AsRateLimitError(err)
	require.False(t, limited, "할당량이 남은 403 은 권한 오류로 다뤄야 한다")
	require.Contains(t, err.Error(), "403 forbidden")
}

// 429 는 항상 rate limit 이다.
func TestFetcher_TooManyRequests_IsRateLimit(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {

		return jsonResp(http.StatusTooManyRequests, nil), nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/o", "r", "values.yaml", "", "tok")
	require.Error(t, err)

	rle, ok := AsRateLimitError(err)
	require.True(t, ok)
	require.Equal(t, FallbackRateLimitBackoff, rle.RetryAfter, "헤더가 없으면 폴백 백오프를 쓴다")
}

// 이미 지난 리셋 시각이 오더라도 0 이나 음수로 requeue 하지 않아야 한다.
func TestRetryAfter_ClampsPastReset(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)

	h := http.Header{}
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(-time.Hour).Unix(), 10))

	snap := parseRateLimit(h)
	require.True(t, snap.Known)

	got := retryAfterFrom(h, snap, now)
	require.Equal(t, MinRateLimitBackoff, got)
}

func TestRetryAfter_ClampsAbsurdReset(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)

	h := http.Header{}
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(72*time.Hour).Unix(), 10))

	got := retryAfterFrom(h, parseRateLimit(h), now)
	require.Equal(t, MaxRateLimitBackoff, got)
}

// Fetcher 와 캐시는 MaxConcurrentReconciles > 1 일 때 여러 reconcile 이 공유한다.
// -race 와 함께 돌려 캐시 접근에 데이터 레이스가 없는지 확인한다.
func TestFetcher_ConcurrentFetchesShareCacheSafely(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	var mu sync.Mutex

	stub.handler = func(r *http.Request) (*http.Response, error) {

		resp := jsonResp(http.StatusOK, contentResp{
			Encoding: "base64",
			Content:  b64WithNewline("k: v\n"),
			SHA:      "blob-1",
		})
		resp.Header.Set("ETag", `"shared"`)

		return resp, nil
	}

	// stubRT.requests 는 락 없이 append 하므로 동시 호출에서는 쓰지 않는다.
	f := NewFetcher(Options{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second, Transport: &lockedRT{inner: stub, mu: &mu}},
		CacheEntries: 4, // 축출을 강제해 put/drop 경로까지 태운다
	})

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			path := fmt.Sprintf("app-%d/values.yaml", i%8)

			_, _, _, err := f.Fetch(ctx, "github.com/o", "r", path, "", "tok")
			require.NoError(t, err)
		}(i)
	}

	wg.Wait()
}

// lockedRT stubRT 의 requests 슬라이스 append 를 직렬화한다.
// stubRT 자체는 락이 없으므로, 테스트 하네스 쪽 레이스와 캐시 쪽 레이스를
// 구분하기 위해 여기서 감싼다.
type lockedRT struct {
	inner http.RoundTripper
	mu    *sync.Mutex
}

func (l *lockedRT) RoundTrip(r *http.Request) (*http.Response, error) {

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.inner.RoundTrip(r)
}

// rate limit 에 걸린 토큰은 리셋 전까지 GitHub 를 다시 부르지 않는다. 대상 변경 이벤트나 status
// 기록 재시도로 reconcile 이 poll 주기와 무관하게 돌아도 요청이 나가지 않아야 한다.
func TestFetcher_DoesNotCallGitHubBeforeRateLimitResets(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	limited := true
	stub.handler = func(r *http.Request) (*http.Response, error) {
		if limited {

			resp := jsonResp(http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
			resp.Header.Set("X-RateLimit-Remaining", "0")
			resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(60*time.Second).Unix(), 10))

			return resp, nil
		}

		return jsonResp(http.StatusOK, contentResp{Encoding: "base64", Content: b64WithNewline("a: b"), SHA: "sha"}), nil
	}

	f := NewFetcher(Options{HTTPClient: &http.Client{Transport: stub}, Now: func() time.Time { return now }})

	_, _, _, err := f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "tok")
	_, isLimited := AsRateLimitError(err)
	require.True(t, isLimited)
	require.Len(t, stub.requests, 1)

	now = now.Add(20 * time.Second)
	_, _, _, err = f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "tok")
	rle, isLimited := AsRateLimitError(err)
	require.True(t, isLimited, "still limited: answered from memory")
	require.Len(t, stub.requests, 1, "no request may be sent before the reset")
	require.Equal(t, 40*time.Second, rle.RetryAfter, "RetryAfter is the time left")

	_, _, _, err = f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "other-token")
	_, isLimited = AsRateLimitError(err)
	require.True(t, isLimited)
	require.Len(t, stub.requests, 2, "other tokens have their own limit")

	limited = false
	now = now.Add(41 * time.Second)
	_, _, _, err = f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "tok")
	require.NoError(t, err)
	require.Len(t, stub.requests, 3, "requests resume after the reset")
}

// rate limit 중 같은 제한에 대한 메시지는 시간이 지나도 같아야 한다(바뀌면 그때마다 status 를 다시 쓴다).
func TestFetcher_RateLimitMessageIsStableWhileLimited(t *testing.T) {
	ctx := context.Background()

	now := time.Unix(1_700_000_000, 0)
	stub := &stubRT{t: t}
	stub.handler = func(r *http.Request) (*http.Response, error) {
		resp := jsonResp(http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
		resp.Header.Set("X-RateLimit-Remaining", "0")
		resp.Header.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(60*time.Second).Unix(), 10))

		return resp, nil
	}

	f := NewFetcher(Options{HTTPClient: &http.Client{Transport: stub}, Now: func() time.Time { return now }})

	_, _, _, first := f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "tok")
	require.Error(t, first)

	now = now.Add(17*time.Second + 123*time.Millisecond)
	_, _, _, second := f.Fetch(ctx, "github.com/acme", "repo", "values.yaml", "", "tok")
	require.Error(t, second)

	require.Equal(t, first.Error(), second.Error())
	require.Contains(t, first.Error(), "retry after 2023-11-14T22:14:20Z")
}

// 풀린 기록은 새 기록을 넣을 때 정리되어, 다시 쓰이지 않는 토큰의 기록이 쌓이지 않는다.
func TestFetcher_ExpiredRateLimitEntriesAreSwept(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)
	f := NewFetcher(Options{Now: func() time.Time { return now }})

	f.rememberLimit("old-token", &RateLimitError{RetryAfter: time.Minute})
	now = now.Add(2 * time.Minute)
	f.rememberLimit("new-token", &RateLimitError{RetryAfter: time.Minute})

	f.limitedMu.Lock()
	defer f.limitedMu.Unlock()
	require.Len(t, f.limitedAt, 1)
	_, stillThere := f.limitedAt[limitKey("old-token")]
	require.False(t, stillThere)
}
