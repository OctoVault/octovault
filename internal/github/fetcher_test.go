package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ---- test helpers ------------------------------------------------------------

type stubRT struct {
	t        *testing.T
	handler  func(*http.Request) (*http.Response, error)
	requests []*http.Request
}

func (s *stubRT) RoundTrip(r *http.Request) (*http.Response, error) {
	s.requests = append(s.requests, r)
	return s.handler(r)
}

func jsonResp(status int, v any) *http.Response {
	var body []byte
	if v != nil {
		body, _ = json.Marshal(v)
	} else {
		body = []byte("{}")
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

func b64WithNewline(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s)) + "\n"
}

// ---- tests -------------------------------------------------------------------

func TestFetcher_Fetch_PerCallRef_AndSchema_CommitWins(t *testing.T) {
	ctx := context.Background()

	const (
		owner      = "acme"
		repo       = "octo"
		valuesPath = "app/values.yaml"
		perRef     = "feature/ab"
		token      = "tok123"
	)

	valuesB64 := b64WithNewline("k: v\n")
	schemaB64 := b64WithNewline(`{"type":"object"}`)
	blobSHA := "blobsha1234567"
	commitSHA := "commitsha42"

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}

	f := NewFetcher(Options{
		BaseURL:        "https://api.github.com",
		HTTPClient:     client,
		SchemaFileName: "validator.schema.json",
		Ref:            "main", // default ref (should be overridden by per-call ref)
		UserAgent:      "utest",
	})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		u := r.URL
		qs := u.Query()
		// values
		if strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/contents/app/values.yaml") {
			require.Equal(t, perRef, qs.Get("ref")) // per-call ref 우선
			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  valuesB64,
				SHA:      blobSHA,
				Name:     "values.yaml",
				Path:     "app/values.yaml",
				Type:     "file",
			}), nil
		}
		// schema
		if strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/contents/app/validator.schema.json") {
			require.Equal(t, perRef, qs.Get("ref"))
			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  schemaB64,
				SHA:      "schemasha",
				Name:     "validator.schema.json",
				Path:     "app/validator.schema.json",
				Type:     "file",
			}), nil
		}
		// commits
		if strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/commits") {
			require.Equal(t, "app/values.yaml", qs.Get("path"))
			require.Equal(t, "1", qs.Get("per_page"))
			require.Equal(t, perRef, qs.Get("sha")) // ref=feature/ab 로 pin
			return jsonResp(http.StatusOK, []commitResp{{SHA: commitSHA}}), nil
		}
		return jsonResp(http.StatusNotFound, nil), nil
	}

	values, schema, rev, err := f.Fetch(ctx, "github.com/"+owner, repo, valuesPath, perRef, token)
	require.NoError(t, err)
	require.Equal(t, []byte("k: v\n"), values)
	require.Equal(t, []byte(`{"type":"object"}`), schema)
	require.Equal(t, commitSHA, rev) // commit sha가 우선

	// Authorization/User-Agent 헤더가 붙는지 간단 확인
	require.NotEmpty(t, stub.requests)
	for _, r := range stub.requests {
		require.Equal(t, "Bearer "+token, r.Header.Get("Authorization"))
		require.Equal(t, "utest", r.Header.Get("User-Agent"))
	}
}

func TestFetcher_Fetch_FallbackToBlobSHA_WhenCommitMissing(t *testing.T) {
	ctx := context.Background()

	const (
		owner      = "acme"
		repo       = "octo"
		valuesPath = "app/values.yaml"
		defRef     = "main"
		token      = "tok"
	)
	valuesB64 := b64WithNewline("foo: bar\n")
	blobSHA := "blobcafebabe"

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}

	f := NewFetcher(Options{
		BaseURL:        "https://api.github.com",
		HTTPClient:     client,
		SchemaFileName: "validator.schema.json",
		Ref:            defRef,
	})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		u := r.URL
		q := u.Query()
		switch {
		case strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/contents/app/values.yaml"):
			require.Equal(t, defRef, q.Get("ref")) // per-call ref 비었으므로 default ref 사용
			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  valuesB64,
				SHA:      blobSHA,
			}), nil
		case strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/contents/app/validator.schema.json"):
			require.Equal(t, defRef, q.Get("ref"))
			// 스키마는 отсутств → 404 허용
			return jsonResp(http.StatusNotFound, nil), nil
		case strings.HasSuffix(u.Path, "/repos/"+owner+"/"+repo+"/commits"):
			// 커밋 조회 실패 → 빈 또는 404 → blobSHA 폴백
			return jsonResp(http.StatusNotFound, nil), nil
		default:
			return jsonResp(http.StatusNotFound, nil), nil
		}
	}

	values, schema, rev, err := f.Fetch(ctx, "github.com/"+owner, repo, valuesPath, "", token)
	require.NoError(t, err)
	require.Equal(t, []byte("foo: bar\n"), values)
	require.Nil(t, schema)             // 스키마 404 → nil
	require.Equal(t, blobSHA, rev)     // 폴백
	require.NotEmpty(t, stub.requests) // 호출은 있었음
}

func TestFetcher_Fetch_404_OnValues(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/contents/") {
			return jsonResp(http.StatusNotFound, nil), nil
		}
		return jsonResp(http.StatusOK, nil), nil
	}

	_, _, _, err := f.Fetch(ctx, "github.com/org", "repo", "values.yaml", "", "t")
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetch values.yaml failed")
	require.Contains(t, err.Error(), "404 not found")
}

func TestFetcher_Fetch_DefaultRefUsed_WhenPerCallEmpty(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{
		BaseURL:        "https://api.github.com",
		HTTPClient:     client,
		SchemaFileName: "validator.schema.json",
		Ref:            "default-branch",
	})

	valuesB64 := b64WithNewline("a: 1\n")

	stub.handler = func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		switch {
		case strings.Contains(r.URL.Path, "/contents/values.yaml"):
			require.Equal(t, "default-branch", q.Get("ref"))
			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  valuesB64,
				SHA:      "blob-1",
			}), nil
		case strings.Contains(r.URL.Path, "/contents/validator.schema.json"):
			require.Equal(t, "default-branch", q.Get("ref"))
			return jsonResp(http.StatusNotFound, nil), nil
		case strings.Contains(r.URL.Path, "/commits"):
			require.Equal(t, "default-branch", q.Get("sha"))
			require.Equal(t, "values.yaml", q.Get("path"))
			require.Equal(t, "1", q.Get("per_page"))
			return jsonResp(http.StatusOK, []commitResp{{SHA: "c1"}}), nil
		default:
			return jsonResp(http.StatusNotFound, nil), nil
		}
	}

	v, s, rev, err := f.Fetch(ctx, "github.com/x", "y", "values.yaml", "", "tok")
	require.NoError(t, err)
	require.Equal(t, []byte("a: 1\n"), v)
	require.Nil(t, s)
	require.Equal(t, "c1", rev)
}

func TestFetcher_Fetch_PathEscaping(t *testing.T) {
	ctx := context.Background()

	const fp = "test/resources/config-secret.yaml"
	encoded := "/repos/octovault/octovault/contents/test/resources/config-secret.yaml"

	valuesB64 := b64WithNewline("ok\n")
	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, encoded) {
			return jsonResp(http.StatusOK, contentResp{
				Encoding: "base64",
				Content:  valuesB64,
				SHA:      "blob",
			}), nil
		}
		if strings.Contains(r.URL.Path, "/commits") {
			// path 쿼리 파라미터는 선행 슬래시 없이 raw 값이어야 함
			uq, _ := url.QueryUnescape(r.URL.RawQuery)
			require.Contains(t, uq, "path="+fp)
			return jsonResp(http.StatusOK, []commitResp{}), nil // empty → blob 폴백
		}
		// schema 404
		if strings.Contains(r.URL.Path, "/contents/validator.schema.json") {
			return jsonResp(http.StatusNotFound, nil), nil
		}
		return jsonResp(http.StatusNotFound, nil), nil
	}

	v, s, rev, err := f.Fetch(ctx, "github.com/octovault", "octovault", "/"+fp, "main", "")
	require.NoError(t, err)
	require.Equal(t, []byte("ok\n"), v)
	require.Nil(t, s)
	require.Equal(t, "blob", rev)
}

func TestFetcher_fetchContentBase64_UnsupportedEncoding(t *testing.T) {
	ctx := context.Background()

	stub := &stubRT{t: t}
	client := &http.Client{Timeout: 5 * time.Second, Transport: stub}
	f := NewFetcher(Options{HTTPClient: client})

	stub.handler = func(r *http.Request) (*http.Response, error) {
		return jsonResp(http.StatusOK, contentResp{
			Encoding: "utf-16", // not supported
			Content:  "deadbeef",
			SHA:      "x",
		}), nil
	}

	_, _, err := f.fetchContentBase64(ctx, "https://api.github.com/whatever", "tok")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported encoding")
}
