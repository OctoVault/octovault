// Package jsonkey AWS 시크릿/파라미터 값에서 점(.)으로 구분된 경로의 값을 꺼낸다.
// Secrets Manager 와 Parameter Store 가 같은 규칙을 쓴다.
package jsonkey

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Extract value 를 JSON 으로 해석해 jsonKey("a.b.c") 위치의 값을 반환한다.
// 문자열이면 그대로, 그 외 타입은 JSON 으로 직렬화해 반환한다.
func Extract(value []byte, jsonKey string) ([]byte, error) {
	if strings.TrimSpace(jsonKey) == "" {

		return nil, errors.New("jsonKey required")
	}

	var t interface{}
	if err := json.Unmarshal(value, &t); err != nil {

		return nil, fmt.Errorf("parse json: %w", err)
	}

	cur := t
	for _, part := range strings.Split(jsonKey, ".") {

		m, ok := cur.(map[string]interface{})
		if !ok {

			return nil, fmt.Errorf("path %q not found (non-object at %q)", jsonKey, part)
		}

		next, ok := m[part]
		if !ok {

			return nil, fmt.Errorf("json key %q not found", part)
		}

		cur = next
	}

	if s, ok := cur.(string); ok {

		return []byte(s), nil
	}

	b, err := json.Marshal(cur)
	if err != nil {

		return nil, fmt.Errorf("marshal value at %q: %w", jsonKey, err)
	}

	return b, nil
}
