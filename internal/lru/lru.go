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

// Put 값을 넣는다. 크기를 넘어 밀려난 항목 수를 반환한다(호출자가 지표로 쓸 수 있다).
func (c *Cache[V]) Put(key string, value V) int {
	if c == nil {

		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {

		el.Value.(*record[V]).value = value
		c.order.MoveToFront(el)

		return 0
	}

	c.entries[key] = c.order.PushFront(&record[V]{key: key, value: value})

	evicted := 0
	for c.order.Len() > c.max {

		oldest := c.order.Back()
		if oldest == nil {

			break
		}

		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*record[V]).key)
		evicted++
	}

	return evicted
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

// DropIf key 의 현재 값이 pred 를 만족할 때만 지운다. 확인과 삭제를 한 락 안에서 하므로,
// 값을 읽은 뒤 다른 고루틴이 새 값을 넣었다면 그 새 값은 지우지 않는다. 지웠으면 true.
func (c *Cache[V]) DropIf(key string, pred func(V) bool) bool {
	if c == nil {

		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok || !pred(el.Value.(*record[V]).value) {

		return false
	}

	c.order.Remove(el)
	delete(c.entries, key)

	return true
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
