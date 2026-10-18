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
