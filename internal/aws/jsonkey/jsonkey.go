// Package jsonkey AWS 시크릿/파라미터 값에서 점(.)으로 구분된 경로의 값을 꺼낸다.
// Secrets Manager 와 Parameter Store 가 같은 규칙을 쓴다.
package jsonkey

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Extract value 를 JSON 으로 해석해 jsonKey("a.b.c") 위치의 값을 반환한다.
// 문자열이면 그대로, 그 외 타입은 JSON 으로 직렬화해 반환한다.
func Extract(value []byte, jsonKey string) ([]byte, error) {
	if strings.TrimSpace(jsonKey) == "" {

		return nil, errors.New("jsonKey required")
	}

	t, err := decode(value)
	if err != nil {

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

	switch v := cur.(type) {
	case string:
		return []byte(v), nil
	case json.Number:
		return []byte(v.String()), nil
	}

	b, err := json.Marshal(cur)
	if err != nil {

		return nil, fmt.Errorf("marshal value at %q: %w", jsonKey, err)
	}

	return b, nil
}

// decode 숫자를 float64 가 아니라 json.Number 로 읽어 원래 표기를 그대로 보존한다.
// json.Unmarshal 처럼 값 뒤에 다른 내용이 있으면 에러로 본다.
func decode(value []byte) (interface{}, error) {

	dec := json.NewDecoder(bytes.NewReader(value))
	dec.UseNumber()

	var t interface{}
	if err := dec.Decode(&t); err != nil {

		return nil, err
	}

	if _, err := dec.Token(); err != io.EOF {

		return nil, errors.New("unexpected data after the JSON value")
	}

	return t, nil
}
