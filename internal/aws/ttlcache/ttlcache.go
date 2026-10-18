// Package ttlcache AWS 조회 결과를 위한 크기 제한 TTL 캐시.
//
// 같은 키를 동시에 조회하면 AWS 호출은 한 번만 나간다(singleflight). 여러 OctoVault 가
// 같은 시크릿을 참조할 때 TTL 만료 직후 요청이 몰려 throttling 되는 것을 막는다.
package ttlcache

import (
	"context"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/octovault/octovault/internal/lru"
)

const (
	// DefaultMaxEntries 기본 최대 항목 수. 가득 차면 가장 오래 쓰이지 않은 항목부터 지운다.
	DefaultMaxEntries = lru.DefaultEntries

	// DefaultLoadTimeout 한 번의 load 에 허용하는 시간.
	DefaultLoadTimeout = 30 * time.Second
)

type entry[V any] struct {
	value V
	exp   time.Time
}

type Cache[V any] struct {
	ttl         time.Duration
	max         int
	loadTimeout time.Duration
	entries     *lru.Cache[entry[V]]
	group       singleflight.Group
	now         func() time.Time
	onEvict     func(n int)
}

// Option Cache 생성 옵션.
type Option[V any] func(*Cache[V])

// WithMaxEntries 최대 항목 수. 0 이하면 DefaultMaxEntries.
func WithMaxEntries[V any](n int) Option[V] {
	return func(c *Cache[V]) {

		c.max = n
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

// WithEvictHook 크기 한도 때문에 항목이 밀려날 때마다 밀려난 수와 함께 호출된다(지표용).
func WithEvictHook[V any](fn func(n int)) Option[V] {
	return func(c *Cache[V]) {

		c.onEvict = fn
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
		loadTimeout: DefaultLoadTimeout,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}

	c.entries = lru.New[entry[V]](c.max)

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

func (c *Cache[V]) store(key string, v V) {
	if n := c.entries.Put(key, entry[V]{value: v, exp: c.now().Add(c.ttl)}); n > 0 && c.onEvict != nil {

		c.onEvict(n)
	}
}

// Len 현재 항목 수.
func (c *Cache[V]) Len() int {
	return c.entries.Len()
}

// lookup 만료된 항목은 발견 즉시 지운다. 더 이상 참조하지 않는 복호화된 값이 메모리에 남지 않게 한다.
func (c *Cache[V]) lookup(key string) (V, bool) {

	var zero V
	e, ok := c.entries.Get(key)
	if !ok {

		return zero, false
	}

	if !e.exp.After(c.now()) {

		c.dropIfUnchanged(key, e)
		return zero, false
	}

	return e.value, true
}

// dropIfUnchanged 읽어 온 만료 항목이 그대로 있을 때만 지운다. 확인한 뒤 singleflight 로 새 값이
// 들어왔다면(만료 시각이 다르다) 그 값은 남긴다. 그렇지 않으면 방금 채운 값을 지워 AWS 호출이
// 다시 몰린다.
func (c *Cache[V]) dropIfUnchanged(key string, seen entry[V]) {
	c.entries.DropIf(key, func(cur entry[V]) bool {
		return cur.exp.Equal(seen.exp)
	})
}
