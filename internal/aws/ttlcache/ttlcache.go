// Package ttlcache AWS 조회 결과를 위한 크기 제한 TTL 캐시.
//
// 같은 키를 동시에 조회하면 AWS 호출은 한 번만 나간다(singleflight). 여러 OctoVault 가
// 같은 시크릿을 참조할 때 TTL 만료 직후 요청이 몰려 throttling 되는 것을 막는다.
package ttlcache

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	// DefaultMaxEntries 기본 최대 항목 수.
	DefaultMaxEntries = 1024

	// DefaultLoadTimeout 한 번의 load 에 허용하는 시간.
	DefaultLoadTimeout = 30 * time.Second
)

type entry[V any] struct {
	value V
	exp   time.Time
}

type Cache[V any] struct {
	mu          sync.Mutex
	ttl         time.Duration
	max         int
	loadTimeout time.Duration
	entries     map[string]entry[V]
	group       singleflight.Group
	now         func() time.Time
}

// Option Cache 생성 옵션.
type Option[V any] func(*Cache[V])

// WithMaxEntries 최대 항목 수. 0 이하면 DefaultMaxEntries.
func WithMaxEntries[V any](n int) Option[V] {
	return func(c *Cache[V]) {
		if n > 0 {

			c.max = n
		}
	}
}

// WithLoadTimeout load 한 번에 허용하는 시간. 0 이하면 DefaultLoadTimeout.
func WithLoadTimeout[V any](d time.Duration) Option[V] {
	return func(c *Cache[V]) {
		if d > 0 {

			c.loadTimeout = d
		}
	}
}

// WithClock 테스트용 시계.
func WithClock[V any](now func() time.Time) Option[V] {
	return func(c *Cache[V]) {

		c.now = now
	}
}

func New[V any](ttl time.Duration, opts ...Option[V]) *Cache[V] {

	c := &Cache[V]{
		ttl:         ttl,
		max:         DefaultMaxEntries,
		loadTimeout: DefaultLoadTimeout,
		entries:     make(map[string]entry[V]),
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Get 캐시에 유효한 값이 있으면 돌려주고, 없으면 load 로 채운다. 실패는 캐시하지 않는다.
//
// 같은 키에 대한 동시 호출은 load 를 한 번만 실행하고 결과를 공유한다. load 는 어느 한 호출자의
// ctx 에 묶이지 않는다. 처음 요청한 reconcile 이 취소돼도 기다리던 다른 호출자까지 실패하지
// 않도록, 호출자 ctx 의 값만 물려받고 취소는 끊은 ctx 에 loadTimeout 을 걸어 실행한다.
// 각 호출자는 자기 ctx 가 끝나면 결과를 기다리지 않고 바로 돌아간다.
func (c *Cache[V]) Get(ctx context.Context, key string, load func(context.Context) (V, error)) (V, error) {
	if v, ok := c.lookup(key); ok {

		return v, nil
	}

	ch := c.group.DoChan(key, func() (any, error) {
		// 앞선 호출이 방금 채웠을 수 있다.
		if v, ok := c.lookup(key); ok {

			return v, nil
		}

		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.loadTimeout)
		defer cancel()

		v, err := load(lctx)
		if err == nil {

			c.store(key, v)
		}

		return v, err
	})

	select {
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	case res := <-ch:
		v, _ := res.Val.(V)
		return v, res.Err
	}
}

// Len 현재 항목 수(만료됐지만 아직 정리되지 않은 항목 포함).
func (c *Cache[V]) Len() int {

	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

func (c *Cache[V]) lookup(key string) (V, bool) {

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok || !e.exp.After(c.now()) {

		var zero V
		return zero, false
	}

	return e.value, true
}

func (c *Cache[V]) store(key string, v V) {

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.max {
		c.evictLocked(now)
	}

	c.entries[key] = entry[V]{value: v, exp: now.Add(c.ttl)}
}

// evictLocked 만료된 항목을 모두 지우고, 그래도 가득 차 있으면 가장 먼저 만료될 항목 하나를 지운다.
func (c *Cache[V]) evictLocked(now time.Time) {

	var oldestKey string
	var oldestExp time.Time
	for k, e := range c.entries {
		if !e.exp.After(now) {

			delete(c.entries, k)
			continue
		}

		if oldestKey == "" || e.exp.Before(oldestExp) {

			oldestKey, oldestExp = k, e.exp
		}
	}

	if len(c.entries) >= c.max && oldestKey != "" {

		delete(c.entries, oldestKey)
	}
}
