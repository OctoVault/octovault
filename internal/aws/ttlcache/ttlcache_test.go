package ttlcache

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_HitMissAndExpiry(t *testing.T) {

	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithClock[string](func() time.Time { return now }))

	loads := 0
	load := func(context.Context) (string, error) {
		loads++

		return "v" + strconv.Itoa(loads), nil
	}

	v, err := c.Get(ctx, "k", load)
	require.NoError(t, err)
	require.Equal(t, "v1", v)

	v, _ = c.Get(ctx, "k", load)
	require.Equal(t, "v1", v, "cached within TTL")

	now = now.Add(61 * time.Second)
	v, _ = c.Get(ctx, "k", load)
	require.Equal(t, "v2", v, "reloaded after TTL")
}

func TestCache_ExpiredEntryIsDroppedOnLookup(t *testing.T) {

	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithClock[string](func() time.Time { return now }))

	_, err := c.Get(ctx, "k", func(context.Context) (string, error) { return "secret", nil })
	require.NoError(t, err)
	require.Equal(t, 1, c.Len())

	now = now.Add(2 * time.Minute)
	_, err = c.Get(ctx, "k", func(context.Context) (string, error) { return "", errors.New("gone") })
	require.Error(t, err)
	require.Equal(t, 0, c.Len(), "an expired value must not stay in memory")
}

func TestCache_ErrorsAreNotCached(t *testing.T) {

	ctx := context.Background()
	c := New[string](time.Minute)

	_, err := c.Get(ctx, "k", func(context.Context) (string, error) { return "", errors.New("boom") })
	require.Error(t, err)

	v, err := c.Get(ctx, "k", func(context.Context) (string, error) { return "ok", nil })
	require.NoError(t, err)
	require.Equal(t, "ok", v)
}

func TestCache_IsBoundedAndEvictsLeastRecentlyUsed(t *testing.T) {

	ctx := context.Background()
	c := New(time.Minute, WithMaxEntries[int](3))
	put := func(k string, v int) {
		_, err := c.Get(ctx, k, func(context.Context) (int, error) { return v, nil })
		require.NoError(t, err)
	}

	put("a", 1)
	put("b", 2)
	put("c", 3)
	put("a", -1) // 적중: a 가 가장 최근에 쓰인 항목이 된다
	put("d", 4)  // b 가 가장 오래 쓰이지 않았으므로 축출된다

	require.Equal(t, 3, c.Len())

	reloaded := false
	_, _ = c.Get(ctx, "b", func(context.Context) (int, error) { reloaded = true; return 2, nil })
	require.True(t, reloaded, "b must have been evicted")

	v, _ := c.Get(ctx, "a", func(context.Context) (int, error) { return -1, nil })
	require.Equal(t, 1, v, "a must have survived")
}

func TestCache_ConcurrentMissesLoadOnce(t *testing.T) {

	ctx := context.Background()
	c := New[string](time.Minute)

	var loads atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	const callers = 20
	results := make(chan error, callers)
	get := func() {
		v, err := c.Get(ctx, "k", func(context.Context) (string, error) {
			if loads.Add(1) == 1 {

				close(started)
			}

			<-release

			return "v", nil
		})
		if err == nil && v != "v" {

			err = errors.New("unexpected value " + v)
		}

		results <- err
	}

	// 결과가 타이밍과 무관하게 정해지는 이유: 첫 호출은 release 전까지 load 안에서 막혀 있다.
	// 나머지 호출은 (a) 그 진행 중인 호출에 합류하거나, (b) release 뒤에 도착하면 이미 저장된
	// 값을 lookup 또는 DoChan 안의 재확인에서 읽는다. 값은 진행 중인 호출이 끝나기 전에 저장되므로
	// 어느 경로든 load 는 다시 실행되지 않는다. 그래서 loads 는 항상 1 이다.
	go get()
	<-started
	var wg sync.WaitGroup
	for range callers - 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			get()
		}()
	}

	close(release)
	wg.Wait()
	for range callers {
		assert.NoError(t, <-results)
	}

	assert.Equal(t, int32(1), loads.Load())
}

// 처음 요청한 쪽이 취소돼도, 함께 기다리던 다른 호출자는 결과를 받아야 한다.
func TestCache_FirstCallerCancellationDoesNotFailOthers(t *testing.T) {

	c := New[string](time.Minute)

	started := make(chan struct{})
	release := make(chan struct{})
	load := func(ctx context.Context) (string, error) {
		close(started)
		select {
		case <-release:
			return "v", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() {
		_, err := c.Get(firstCtx, "k", load)
		firstErr <- err
	}()
	<-started

	secondDone := make(chan error, 1)
	go func() {
		v, err := c.Get(context.Background(), "k", load)
		if err == nil && v != "v" {

			err = errors.New("unexpected value " + v)
		}

		secondDone <- err
	}()

	cancelFirst()
	require.ErrorIs(t, <-firstErr, context.Canceled, "the cancelled caller returns immediately")

	close(release)
	require.NoError(t, <-secondDone, "the other caller still gets the result")
}

// 기다리는 쪽 ctx 가 끝나면 load 가 끝나기를 기다리지 않고 바로 돌아간다.
func TestCache_WaiterReturnsWhenItsContextEnds(t *testing.T) {

	c := New[string](time.Minute)
	release := make(chan struct{})
	defer close(release)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := c.Get(ctx, "k", func(context.Context) (string, error) {
		<-release

		return "v", nil
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestCache_LoadHasItsOwnTimeout(t *testing.T) {

	c := New(time.Minute, WithLoadTimeout[string](20*time.Millisecond))

	_, err := c.Get(context.Background(), "k", func(ctx context.Context) (string, error) {
		<-ctx.Done()

		return "", ctx.Err()
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

// 만료 항목을 읽은 뒤 지우기 전에 새 값이 들어오면, 새 값은 지워지지 않아야 한다.
func TestCache_ExpiredDropKeepsFreshlyStoredValue(t *testing.T) {

	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithClock[string](func() time.Time { return now }))

	_, err := c.Get(ctx, "k", func(context.Context) (string, error) { return "old", nil })
	require.NoError(t, err)
	stale, ok := c.entries.Get("k")
	require.True(t, ok)

	// 만료 후 다른 호출이 새 값을 넣은 상황을 만든다.
	now = now.Add(2 * time.Minute)
	c.entries.Put("k", entry[string]{value: "fresh", exp: now.Add(time.Minute)})

	// 앞서 읽어 둔 만료 항목 기준으로 지우려 해도 새 값은 남아야 한다.
	c.dropIfUnchanged("k", stale)

	v, err := c.Get(ctx, "k", func(context.Context) (string, error) { return "reloaded", nil })
	require.NoError(t, err)
	require.Equal(t, "fresh", v)
}
