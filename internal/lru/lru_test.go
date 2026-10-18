package lru

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLRU_EvictsOldestBeyondCapacity(t *testing.T) {

	c := New[string](2)
	c.Put("a", "1")
	c.Put("b", "2")
	c.Put("c", "3")

	_, ok := c.Get("a")
	require.False(t, ok, "가장 오래된 항목이 축출돼야 한다")

	for _, k := range []string{"b", "c"} {
		_, ok := c.Get(k)
		require.True(t, ok, fmt.Sprintf("%s 는 남아있어야 한다", k))
	}
}

func TestLRU_DropIf(t *testing.T) {

	c := New[int](4)
	c.Put("a", 1)

	require.False(t, c.DropIf("a", func(v int) bool { return v == 2 }), "a different value must be kept")
	_, ok := c.Get("a")
	require.True(t, ok)

	require.True(t, c.DropIf("a", func(v int) bool { return v == 1 }))
	_, ok = c.Get("a")
	require.False(t, ok)

	require.False(t, c.DropIf("missing", func(int) bool { return true }))
}

func TestLRU_PutReportsEvictions(t *testing.T) {

	c := New[int](2)
	require.Equal(t, 0, c.Put("a", 1))
	require.Equal(t, 0, c.Put("b", 2))
	require.Equal(t, 0, c.Put("a", 3), "updating an existing key evicts nothing")
	require.Equal(t, 1, c.Put("c", 4))
}
