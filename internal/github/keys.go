package github

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/octovault/octovault/internal/lru"
)

// DefaultCacheEntries ETag/자격증명 검증 캐시의 기본 크기.
const DefaultCacheEntries = lru.DefaultEntries

// credentialScopedKey 같은 대상이라도 자격증명이 다르면 응답이 달라질 수 있으므로
// 토큰 지문을 키에 포함한다. 토큰 원문은 키에 남기지 않는다.
//
// 부수 효과로 토큰이 교체되면 키가 바뀌어 캐시가 자동 무효화된다.
func credentialScopedKey(subject, token string) string {

	sum := sha256.Sum256([]byte(token))

	return subject + "\x00" + hex.EncodeToString(sum[:8])
}
