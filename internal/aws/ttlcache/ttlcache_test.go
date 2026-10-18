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

func TestCache_IsBounded(t *testing.T) {

	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithMaxEntries[int](3), WithClock[int](func() time.Time { return now }))

	for i := range 10 {
		now = now.Add(time.Second)
		_, err := c.Get(ctx, strconv.Itoa(i), func(context.Context) (int, error) { return i, nil })
		require.NoError(t, err)
	}

	require.Equal(t, 3, c.Len())
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

func TestCache_ConcurrentMissesLoadOnce(t *testing.T) {

	ctx := context.Background()
	c := New[string](time.Minute)

	var loads atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	load := func(context.Context) (string, error) {
		if loads.Add(1) == 1 {

			close(started)
		}

		<-release

		return "v", nil
	}

	const callers = 20
	results := make(chan error, callers)
	get := func() {
		v, err := c.Get(ctx, "k", load)
		if err == nil && v != "v" {

			err = errors.New("unexpected value " + v)
		}

		results <- err
	}

	// 첫 호출이 load 안에서 막혀 있는 동안 나머지를 시작하면, 나머지는 반드시 진행 중인
	// 호출에 합류한다. 타이밍에 기대지 않고 결정적으로 검증할 수 있다.
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
