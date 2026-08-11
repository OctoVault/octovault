package github

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// DefaultCacheEntries 기본 캐시 크기.
const DefaultCacheEntries = 1024

// lru 크기 제한이 있는 스레드 안전 LRU.
// MaxConcurrentReconciles > 1 이면 여러 reconcile 이 동시에 접근하므로 락이 필요하다.
type lru[V any] struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	order   *list.List // front = 가장 최근 사용
}

type lruRecord[V any] struct {
	key   string
	value V
}

func newLRU[V any](max int) *lru[V] {
	if max <= 0 {

		max = DefaultCacheEntries
	}

	return &lru[V]{
		max:     max,
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
	}
}

func (c *lru[V]) get(key string) (V, bool) {
	var zero V
	if c == nil {

		return zero, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {

		return zero, false
	}

	c.order.MoveToFront(el)

	return el.Value.(*lruRecord[V]).value, true
}

func (c *lru[V]) put(key string, value V) {
	if c == nil {

		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {

		el.Value.(*lruRecord[V]).value = value
		c.order.MoveToFront(el)

		return
	}

	c.entries[key] = c.order.PushFront(&lruRecord[V]{key: key, value: value})

	for c.order.Len() > c.max {

		oldest := c.order.Back()
		if oldest == nil {

			break
		}

		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*lruRecord[V]).key)
	}
}

func (c *lru[V]) drop(key string) {
	if c == nil {

		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {

		return
	}

	c.order.Remove(el)
	delete(c.entries, key)
}

// credentialScopedKey 같은 대상이라도 자격증명이 다르면 응답이 달라질 수 있으므로
// 토큰 지문을 키에 포함한다. 토큰 원문은 키에 남기지 않는다.
//
// 부수 효과로 토큰이 교체되면 키가 바뀌어 캐시가 자동 무효화된다.
func credentialScopedKey(subject, token string) string {

	sum := sha256.Sum256([]byte(token))

	return subject + "\x00" + hex.EncodeToString(sum[:8])
}
