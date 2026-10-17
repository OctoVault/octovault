package ttlcache

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCache_HitMissAndExpiry(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithClock[string](func() time.Time { return now }))

	loads := 0
	load := func() (string, error) {
		loads++

		return "v" + strconv.Itoa(loads), nil
	}

	v, err := c.Get("k", load)
	require.NoError(t, err)
	require.Equal(t, "v1", v)

	v, _ = c.Get("k", load)
	require.Equal(t, "v1", v, "cached within TTL")

	now = now.Add(61 * time.Second)
	v, _ = c.Get("k", load)
	require.Equal(t, "v2", v, "reloaded after TTL")
}

func TestCache_ErrorsAreNotCached(t *testing.T) {

	c := New[string](time.Minute)

	_, err := c.Get("k", func() (string, error) { return "", errors.New("boom") })
	require.Error(t, err)

	v, err := c.Get("k", func() (string, error) { return "ok", nil })
	require.NoError(t, err)
	require.Equal(t, "ok", v)
}

func TestCache_IsBounded(t *testing.T) {

	now := time.Unix(1_700_000_000, 0)
	c := New(time.Minute, WithMaxEntries[int](3), WithClock[int](func() time.Time { return now }))

	for i := range 10 {
		now = now.Add(time.Second)
		_, err := c.Get(strconv.Itoa(i), func() (int, error) { return i, nil })
		require.NoError(t, err)
	}

	require.Equal(t, 3, c.Len())

	// 가장 최근 키는 남아 있어야 한다.
	v, _ := c.Get("9", func() (int, error) { return -1, nil })
	require.Equal(t, 9, v)
}

func TestCache_ConcurrentMissesLoadOnce(t *testing.T) {

	c := New[string](time.Minute)

	var loads atomic.Int32
	release := make(chan struct{})

	const callers = 20
	var wg sync.WaitGroup
	started := make(chan struct{}, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()

			started <- struct{}{}
			v, err := c.Get("k", func() (string, error) {
				loads.Add(1)
				<-release

				return "v", nil
			})
			require.NoError(t, err)
			require.Equal(t, "v", v)
		}()
	}

	for range callers {
		<-started
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	require.Equal(t, int32(1), loads.Load())
}
