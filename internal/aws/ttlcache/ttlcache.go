// Package ttlcache AWS 조회 결과를 위한 크기 제한 TTL 캐시.
//
// 같은 키를 동시에 조회하면 AWS 호출은 한 번만 나간다(singleflight). 여러 OctoVault 가
// 같은 시크릿을 참조할 때 TTL 만료 직후 요청이 몰려 throttling 되는 것을 막는다.
package ttlcache

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// DefaultMaxEntries 기본 최대 항목 수.
const DefaultMaxEntries = 1024

type entry[V any] struct {
	value V
	exp   time.Time
}

type Cache[V any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]entry[V]
	group   singleflight.Group
	now     func() time.Time
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

// WithClock 테스트용 시계.
func WithClock[V any](now func() time.Time) Option[V] {
	return func(c *Cache[V]) {

		c.now = now
	}
}

func New[V any](ttl time.Duration, opts ...Option[V]) *Cache[V] {

	c := &Cache[V]{
		ttl:     ttl,
		max:     DefaultMaxEntries,
		entries: make(map[string]entry[V]),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Get 캐시에 유효한 값이 있으면 돌려주고, 없으면 load 로 채운다.
// 같은 키에 대한 동시 호출은 load 를 한 번만 실행하고 결과를 공유한다. 실패는 캐시하지 않는다.
func (c *Cache[V]) Get(key string, load func() (V, error)) (V, error) {
	if v, ok := c.lookup(key); ok {

		return v, nil
	}

	out, err, _ := c.group.Do(key, func() (any, error) {
		// 앞선 호출이 방금 채웠을 수 있다.
		if v, ok := c.lookup(key); ok {

			return v, nil
		}

		v, err := load()
		if err != nil {

			return v, err
		}

		c.store(key, v)

		return v, nil
	})

	v, _ := out.(V)

	return v, err
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
