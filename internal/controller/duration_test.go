package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseDurationOr(t *testing.T) {

	const def = 7 * time.Minute

	assert.Equal(t, def, ParseDurationOr("", def))
	assert.Equal(t, def, ParseDurationOr("   ", def))
	assert.Equal(t, def, ParseDurationOr("nope", def))
	assert.Equal(t, def, ParseDurationOr("0s", def))
	assert.Equal(t, def, ParseDurationOr("-1m", def))
	assert.Equal(t, 90*time.Second, ParseDurationOr(" 1m30s ", def))
}
