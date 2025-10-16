package awssm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// ---- 테스트용 HTTP 클라이언트 ----

type getSecretReq struct {
	SecretId *string `json:"SecretId"`
}

type fakeHTTPClient struct {
	// 호출 카운터(캐시 동작 검증용)
	calls int32
	// name -> 응답 생성자
	handlers map[string]func(secretID string) *http.Response
	// 기본 핸들러 (매치 안 될 때)
	defaultHandler func(secretID string) *http.Response
}

func (f *fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&f.calls, 1)

	// AWS Secrets Manager는 X-Amz-Target으로 API를 구분합니다.
	if req.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" {
		return httpResponse(400, map[string]string{
			"x-amzn-errortype": "InvalidRequestException",
		}, map[string]any{
			"__type":  "InvalidRequestException",
			"message": "unsupported target",
		}), nil
	}

	// 요청 body에서 SecretId 추출
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	var in getSecretReq
	_ = json.Unmarshal(body, &in)
	secretID := ""
	if in.SecretId != nil {
		secretID = *in.SecretId
	}

	// name별 핸들러 선택
	if h, ok := f.handlers[secretID]; ok {
		return h(secretID), nil
	}
	if f.defaultHandler != nil {
		return f.defaultHandler(secretID), nil
	}
	return httpResponse(404, map[string]string{
		"x-amzn-errortype": "ResourceNotFoundException",
	}, map[string]any{
		"__type":  "ResourceNotFoundException",
		"message": fmt.Sprintf("secret %q not found", secretID),
	}), nil
}

func httpResponse(status int, headers map[string]string, body any) *http.Response {
	var b []byte
	switch v := body.(type) {
	case []byte:
		b = v
	default:
		b, _ = json.Marshal(v)
	}
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	// smithy는 대소문자 무시하지만 안전하게 둘 다 셋업
	if _, ok := headers["x-amzn-ErrorType"]; ok {
		resp.Header.Set("x-amzn-errortype", headers["x-amzn-ErrorType"])
	}
	if _, ok := headers["x-amzn-errortype"]; ok {
		resp.Header.Set("x-amzn-ErrorType", headers["x-amzn-errortype"])
	}
	return resp
}

// 테스트용 Provider 생성 (실제 AWS 통신 없음)
func newTestProvider(t *testing.T, fh *fakeHTTPClient, ttl time.Duration) *Provider {
	t.Helper()

	cfg := aws.Config{
		Region: "us-east-1",
		// 익명 자격증명 (네트워크 호출 안 함)
		Credentials: aws.AnonymousCredentials{},
		// 우리가 만든 가짜 HTTP 클라이언트 주입
		HTTPClient: fh,
		// 엔드포인트도 임의로 고정
		BaseEndpoint: aws.String("https://example.com"),
	}

	p := &Provider{
		client: sm.NewFromConfig(cfg),
		ttl:    ttl,
		cache:  make(map[string]cacheEntry),
	}
	return p
}

// ---- 테스트들 ----

func TestGetSecret_String_CacheAndMeta(t *testing.T) {
	fh := &fakeHTTPClient{
		handlers: map[string]func(string) *http.Response{
			"my/secret": func(_ string) *http.Response {
				return httpResponse(200, nil, map[string]any{
					"ARN":           "arn:aws:secretsmanager:us-east-1:123456789012:secret:my/secret",
					"Name":          "my/secret",
					"SecretString":  `{"hello":"world","foo":{"bar":"hierarchy"}}`,
					"VersionId":     "v-123",
					"VersionStages": []string{"AWSCURRENT"},
				})
			},
		},
	}
	p := newTestProvider(t, fh, time.Minute)

	// 첫 호출: 네트워크(가짜) 사용
	val, meta, err := p.GetSecret(context.Background(), "my/secret")
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if got, want := string(val), `{"hello":"world","foo":{"bar":"hierarchy"}}`; got != want {
		t.Fatalf("value mismatch: got %s want %s", got, want)
	}
	if meta.VersionID != "v-123" {
		t.Fatalf("VersionID got %s", meta.VersionID)
	}
	if len(meta.VersionStages) != 1 || meta.VersionStages[0] != "AWSCURRENT" {
		t.Fatalf("VersionStages got %v", meta.VersionStages)
	}

	// 두 번째 호출: 캐시 적중 → HTTP 호출은 1회여야 함
	_, _, err = p.GetSecret(context.Background(), "my/secret")
	if err != nil {
		t.Fatalf("GetSecret(2) failed: %v", err)
	}
	if calls := atomic.LoadInt32(&fh.calls); calls != 1 {
		t.Fatalf("expected 1 http call, got %d", calls)
	}
}

func TestGetSecret_Binary(t *testing.T) {
	// SecretBinary는 JSON 내 base64로 전달되며 SDK가 []byte로 디코딩해준다.
	raw := []byte{0x00, 0x01, 0xFE, 0xFF, 'X', 'Y'}
	fh := &fakeHTTPClient{
		handlers: map[string]func(string) *http.Response{
			"bin/secret": func(_ string) *http.Response {
				return httpResponse(200, nil, map[string]any{
					"Name":          "bin/secret",
					"SecretBinary":  base64.StdEncoding.EncodeToString(raw),
					"VersionId":     "v-bin",
					"VersionStages": []string{"AWSPREVIOUS"},
				})
			},
		},
	}
	p := newTestProvider(t, fh, time.Minute)

	val, meta, err := p.GetSecret(context.Background(), "bin/secret")
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if !bytes.Equal(val, raw) {
		t.Fatalf("binary mismatch: got %v want %v", val, raw)
	}
	if meta.VersionID != "v-bin" {
		t.Fatalf("meta.VersionID got %s", meta.VersionID)
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	fh := &fakeHTTPClient{
		defaultHandler: func(secretID string) *http.Response {
			return httpResponse(400, map[string]string{
				// AWS는 4xx에 x-amzn-ErrorType 헤더로 에러 타입을 전달
				"x-amzn-errortype": "ResourceNotFoundException",
			}, map[string]any{
				"__type":  "ResourceNotFoundException",
				"message": "not found",
			})
		},
	}
	p := newTestProvider(t, fh, time.Minute)

	_, _, err := p.GetSecret(context.Background(), "no/such/secret")
	if err == nil || !contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got %v", err)
	}
}

func TestGetSecret_GenericServerError(t *testing.T) {
	fh := &fakeHTTPClient{
		handlers: map[string]func(string) *http.Response{
			"oops": func(_ string) *http.Response {
				return httpResponse(500, nil, map[string]any{
					"message": "internal error",
				})
			},
		},
	}
	p := newTestProvider(t, fh, time.Minute)

	_, _, err := p.GetSecret(context.Background(), "oops")
	if err == nil || !contains(err.Error(), "get secret value") {
		t.Fatalf("expected wrapped generic error, got %v", err)
	}
}

func TestExtractJSONKey(t *testing.T) {
	p := &Provider{}

	src := []byte(`{
		"hello": "world",
		"foo": { "bar": "hierarchy", "n": 42 },
		"arr": [1,2,3]
	}`)

	// 문자열
	out, err := p.ExtractJSONKey(src, "foo.bar")
	if err != nil {
		t.Fatalf("ExtractJSONKey error: %v", err)
	}
	if got, want := string(out), "hierarchy"; got != want {
		t.Fatalf("string extract mismatch: got %s want %s", got, want)
	}

	// 객체 → JSON 직렬화
	out, err = p.ExtractJSONKey(src, "foo")
	if err != nil {
		t.Fatalf("ExtractJSONKey error: %v", err)
	}
	if got := string(out); !jsonEq(got, `{"bar":"hierarchy","n":42}`) {
		t.Fatalf("object extract mismatch: got %s", got)
	}

	// 배열 → JSON 직렬화
	out, err = p.ExtractJSONKey(src, "arr")
	if err != nil {
		t.Fatalf("ExtractJSONKey error: %v", err)
	}
	if got := string(out); !jsonEq(got, `[1,2,3]`) {
		t.Fatalf("array extract mismatch: got %s", got)
	}

	// 오류 경로
	if _, err = p.ExtractJSONKey(src, "foo.nope"); err == nil {
		t.Fatalf("expected error for missing path")
	}
}

func TestCacheExpiry(t *testing.T) {
	// TTL이 짧을 때 만료 후 재호출되는지 확인
	fh := &fakeHTTPClient{
		handlers: map[string]func(string) *http.Response{
			"ttl/secret": func(_ string) *http.Response {
				return httpResponse(200, nil, map[string]any{
					"Name":         "ttl/secret",
					"SecretString": `"v"`,
					"VersionId":    "v-ttl",
				})
			},
		},
	}
	p := newTestProvider(t, fh, 30*time.Millisecond)

	// 1회 호출 → 네트워크
	if _, _, err := p.GetSecret(context.Background(), "ttl/secret"); err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	// 캐시 적중
	if _, _, err := p.GetSecret(context.Background(), "ttl/secret"); err != nil {
		t.Fatalf("GetSecret(2) failed: %v", err)
	}
	if calls := atomic.LoadInt32(&fh.calls); calls != 1 {
		t.Fatalf("expected 1 http call before expiry, got %d", calls)
	}

	// TTL 지나면 다시 호출
	time.Sleep(40 * time.Millisecond)
	if _, _, err := p.GetSecret(context.Background(), "ttl/secret"); err != nil {
		t.Fatalf("GetSecret after expiry failed: %v", err)
	}
	if calls := atomic.LoadInt32(&fh.calls); calls != 2 {
		t.Fatalf("expected 2 http calls after expiry, got %d", calls)
	}
}

// ---- helpers ----

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

// JSON 동등성 비교(공백/필드순서 무시)
func jsonEq(a, b string) bool {
	var ja, jb any
	if json.Unmarshal([]byte(a), &ja) != nil {
		return false
	}
	if json.Unmarshal([]byte(b), &jb) != nil {
		return false
	}
	return deepEqualJSON(ja, jb)
}

func deepEqualJSON(a, b any) bool {
	switch ta := a.(type) {
	case map[string]any:
		tb, ok := b.(map[string]any)
		if !ok || len(ta) != len(tb) {
			return false
		}
		for k, va := range ta {
			vb, ok := tb[k]
			if !ok || !deepEqualJSON(va, vb) {
				return false
			}
		}
		return true
	case []any:
		tb, ok := b.([]any)
		if !ok || len(ta) != len(tb) {
			return false
		}
		for i := range ta {
			if !deepEqualJSON(ta[i], tb[i]) {
				return false
			}
		}
		return true
	default:
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
}
