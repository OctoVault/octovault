// Package lru 크기 제한이 있는 스레드 안전 LRU 캐시.
package lru

import (
	"container/list"
	"sync"
)

// DefaultEntries 기본 최대 항목 수.
const DefaultEntries = 1024

// Cache 크기 제한이 있는 스레드 안전 LRU.
// MaxConcurrentReconciles > 1 이면 여러 reconcile 이 동시에 접근하므로 락이 필요하다.
type Cache[V any] struct {
	mu      sync.Mutex
	max     int
	entries map[string]*list.Element
	order   *list.List // front = 가장 최근 사용
}

type record[V any] struct {
	key   string
	value V
}

// New max 가 0 이하면 DefaultEntries.
func New[V any](max int) *Cache[V] {
	if max <= 0 {

		max = DefaultEntries
	}

	return &Cache[V]{
		max:     max,
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
	}
}

func (c *Cache[V]) Get(key string) (V, bool) {
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

	return el.Value.(*record[V]).value, true
}

func (c *Cache[V]) Put(key string, value V) {
	if c == nil {

		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {

		el.Value.(*record[V]).value = value
		c.order.MoveToFront(el)

		return
	}

	c.entries[key] = c.order.PushFront(&record[V]{key: key, value: value})

	for c.order.Len() > c.max {

		oldest := c.order.Back()
		if oldest == nil {

			break
		}

		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*record[V]).key)
	}
}

func (c *Cache[V]) Drop(key string) {
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

// Len 현재 항목 수.
func (c *Cache[V]) Len() int {
	if c == nil {

		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	return c.order.Len()
}
