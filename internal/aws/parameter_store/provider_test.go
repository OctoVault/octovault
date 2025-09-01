package awsps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/stretchr/testify/require"
)

// --- HTTP RoundTripper Stub ---------------------------------------------------

type rtFunc func(req *http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func jsonResp(status int, v any, hdr http.Header) *http.Response {
	if hdr == nil {
		hdr = make(http.Header)
	}
	// AWS JSON 1.1
	hdr.Set("Content-Type", "application/x-amz-json-1.1")
	var buf bytes.Buffer
	if v != nil {
		_ = json.NewEncoder(&buf).Encode(v)
	}
	return &http.Response{
		StatusCode: status,
		Header:     hdr,
		Body:       io.NopCloser(bytes.NewReader(buf.Bytes())),
	}
}

// --- Helpers ------------------------------------------------------------------

func newProviderWithHTTP(t *testing.T, handler rtFunc, ttl time.Duration) *Provider {
	t.Helper()
	cli := &http.Client{Transport: handler}
	ctx := context.Background()
	p, err := New(ctx, "us-east-1", ttl,
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKID", "SECRET", "")),
		config.WithHTTPClient(cli),
	)
	require.NoError(t, err)
	return p
}

func readJSONBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	_ = r.Body.Close()
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

// --- Tests --------------------------------------------------------------------

const ssmTargetGetParameter = "AmazonSSM.GetParameter"

func TestProvider_GetParameter_Success_AndCache(t *testing.T) {
	callCount := 0
	handler := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Amz-Target") == ssmTargetGetParameter {
			callCount++
			m := readJSONBody(t, r)
			require.Equal(t, "/my/param", m["Name"])
			require.Equal(t, true, m["WithDecryption"])

			// 성공 응답 (AWS JSON 1.1, 날짜는 epoch sec로 내려오는 경우가 일반적이나 테스트에선 생략)
			return jsonResp(200, map[string]any{
				"Parameter": map[string]any{
					"Name":    "/my/param",
					"Type":    "SecureString",
					"Value":   "hello-secret",
					"Version": 3,
					"ARN":     "arn:aws:ssm:us-east-1:123456789012:parameter/my/param",
				},
			}, nil), nil
		}
		return jsonResp(404, map[string]string{"message": "no match"}, nil), nil
	})

	p := newProviderWithHTTP(t, handler, 5*time.Minute)

	// 첫 호출: HTTP 1회
	v1, meta1, err := p.GetParameter(context.Background(), "/my/param", true)
	require.NoError(t, err)
	require.Equal(t, []byte("hello-secret"), v1)
	require.EqualValues(t, 3, meta1.Version)
	require.Equal(t, "SecureString", meta1.Type)
	require.Equal(t, "arn:aws:ssm:us-east-1:123456789012:parameter/my/param", meta1.ARN)
	require.Equal(t, 1, callCount)

	// 두 번째 호출: 캐시 적중 → HTTP 호출 증가 없음
	v2, meta2, err := p.GetParameter(context.Background(), "/my/param", true)
	require.NoError(t, err)
	require.Equal(t, v1, v2)
	require.Equal(t, meta1.Version, meta2.Version)
	require.Equal(t, 1, callCount)
}

func TestProvider_GetParameter_NotFound(t *testing.T) {
	handler := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Amz-Target") == ssmTargetGetParameter {
			// AWS 오류 매핑: x-amzn-errortype 헤더로 에러 타입 전달
			h := make(http.Header)
			h.Set("x-amzn-errortype", "ParameterNotFound")
			return jsonResp(400, map[string]any{
				"message": "Parameter not found",
			}, h), nil
		}
		return jsonResp(404, nil, nil), nil
	})

	p := newProviderWithHTTP(t, handler, time.Minute)

	_, _, err := p.GetParameter(context.Background(), "/not/exist", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), `aws ssm: parameter "/not/exist" not found`)
}

func TestProvider_GetParameter_InvalidKMSKey(t *testing.T) {
	handler := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Amz-Target") == ssmTargetGetParameter {
			h := make(http.Header)
			h.Set("x-amzn-errortype", "InvalidKeyId")
			return jsonResp(400, map[string]any{
				"message": "Invalid KMS key",
			}, h), nil
		}
		return jsonResp(404, nil, nil), nil
	})

	p := newProviderWithHTTP(t, handler, time.Minute)

	_, _, err := p.GetParameter(context.Background(), "/secure", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid kms key")
}

func TestProvider_GetParameter_NoValue(t *testing.T) {
	handler := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Amz-Target") == ssmTargetGetParameter {
			// Value가 없을 때
			return jsonResp(200, map[string]any{
				"Parameter": map[string]any{
					"Name":    "/weird",
					"Type":    "String",
					"Version": 1,
					"ARN":     "arn:aws:ssm:us-east-1:123:parameter/weird",
					// "Value": 누락
				},
			}, nil), nil
		}
		return jsonResp(404, nil, nil), nil
	})

	p := newProviderWithHTTP(t, handler, time.Minute)

	_, _, err := p.GetParameter(context.Background(), "/weird", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), `has no value`)
}

func TestProvider_GetParameter_NameRequired(t *testing.T) {
	p := newProviderWithHTTP(t, rtFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("should not be called")
	}), time.Minute)

	_, _, err := p.GetParameter(context.Background(), "   ", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "parameter name required")
}

func TestProvider_ExtractJSONKey(t *testing.T) {
	p := &Provider{} // ExtractJSONKey는 p.client 사용하지 않음

	raw := []byte(`{
	  "hello":"world",
	  "foo":{"bar":"baz","n": 42, "arr":[1,2,3]}
	}`)

	// 문자열
	out, err := p.ExtractJSONKey(raw, "hello")
	require.NoError(t, err)
	require.Equal(t, []byte("world"), out)

	// 객체 → JSON 직렬
	out, err = p.ExtractJSONKey(raw, "foo")
	require.NoError(t, err)
	require.JSONEq(t, `{"bar":"baz","n":42,"arr":[1,2,3]}`, string(out))

	// 깊은 경로
	out, err = p.ExtractJSONKey(raw, "foo.bar")
	require.NoError(t, err)
	require.Equal(t, []byte("baz"), out)

	// 숫자(비문자열) → JSON 직렬
	out, err = p.ExtractJSONKey(raw, "foo.n")
	require.NoError(t, err)
	require.Equal(t, "42", string(out))

	// 없는 경로
	_, err = p.ExtractJSONKey(raw, "foo.missing")
	require.Error(t, err)
	require.Contains(t, err.Error(), `json key "missing" not found`)

	// 빈 키
	_, err = p.ExtractJSONKey(raw, "  ")
	require.Error(t, err)
	require.Contains(t, err.Error(), "jsonKey required")

	// 잘못된 JSON
	_, err = p.ExtractJSONKey([]byte("{oops"), "hello")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse json")
}

func TestProvider_Cache_Expires(t *testing.T) {
	call := 0
	handler := rtFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Amz-Target") == "AmazonSSM.GetParameter" {
			call++
			return jsonResp(200, map[string]any{
				"Parameter": map[string]any{
					"Name":    "/ttl",
					"Type":    "String",
					"Value":   "v",
					"Version": call, // 매 호출 버전 증가시키면 캐시 효과 확인 가능
					"ARN":     "arn:aws:ssm:us-east-1:123:parameter/ttl",
				},
			}, nil), nil
		}
		return jsonResp(404, nil, nil), nil
	})
	p := newProviderWithHTTP(t, handler, 200*time.Millisecond)

	// 1st
	_, meta1, err := p.GetParameter(context.Background(), "/ttl", false)
	require.NoError(t, err)
	require.EqualValues(t, 1, meta1.Version)
	require.Equal(t, 1, call)

	// 캐시 유지 구간
	_, meta2, err := p.GetParameter(context.Background(), "/ttl", false)
	require.NoError(t, err)
	require.EqualValues(t, 1, meta2.Version)
	require.Equal(t, 1, call)

	// 만료 대기
	time.Sleep(250 * time.Millisecond)

	// 캐시 만료 후 재호출 → call 증가 및 버전 변화
	_, meta3, err := p.GetParameter(context.Background(), "/ttl", false)
	require.NoError(t, err)
	require.EqualValues(t, 2, meta3.Version)
	require.Equal(t, 2, call)
}
