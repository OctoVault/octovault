package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type Options struct {
	BaseURL        string       // e.g. "https://api.github.com"
	HTTPClient     *http.Client // nil = default client
	SchemaFileName string       // default: "validator.schema.json"
	Ref            string       // default ref (fallback when per-call ref is empty)
	UserAgent      string       // default: "octovault-operator"
}

type Fetcher struct {
	baseURL        string
	httpClient     *http.Client
	schemaFileName string
	ref            string
	userAgent      string
}

func NewFetcher(opts Options) *Fetcher {
	base := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if base == "" {
		base = "https://api.github.com"
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	schema := strings.TrimSpace(opts.SchemaFileName)
	if schema == "" {
		schema = "validator.schema.json"
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "octovault-operator"
	}
	return &Fetcher{
		baseURL:        base,
		httpClient:     hc,
		schemaFileName: schema,
		ref:            strings.TrimSpace(opts.Ref),
		userAgent:      ua,
	}
}

// 컨트롤러 인터페이스 준수
var _ interface {
	Fetch(context.Context, string, string, string, string, string) ([]byte, []byte, string, error)
} = (*Fetcher)(nil)

func (f *Fetcher) Fetch(ctx context.Context, org, repo, filePath, ref, token string) ([]byte, []byte, string, error) {
	owner := strings.TrimPrefix(strings.TrimSpace(org), "github.com/")
	if owner == "" {

		return nil, nil, "", errors.New("invalid org: expected 'github.com/<org>'")
	}

	repoName := lastSegment(repo)
	fp := strings.TrimPrefix(filePath, "/")

	// per-call ref > default ref
	refParam := strings.TrimSpace(ref)
	if refParam == "" {

		refParam = f.ref
	}

	// 1) values.yaml
	contentURL := f.apiURL(fmt.Sprintf("/repos/%s/%s/contents/%s",
		url.PathEscape(owner), url.PathEscape(repoName), escapePath(fp)))
	if refParam != "" {

		contentURL += "?ref=" + url.QueryEscape(refParam)
	}

	values, blobSHA, err := f.fetchContentBase64(ctx, contentURL, token)
	if err != nil {

		return nil, nil, "", fmt.Errorf("fetch values.yaml failed: %w", err)
	}

	// 2) schema (optional)
	var schema []byte
	dir := path.Dir("/" + fp)
	if dir == "/" || dir == "." {

		dir = ""
	} else {

		dir = strings.TrimPrefix(dir, "/")
	}

	if f.schemaFileName != "" {

		schemaURL := f.apiURL(fmt.Sprintf("/repos/%s/%s/contents/%s",
			url.PathEscape(owner), url.PathEscape(repoName), escapePath(path.Join(dir, f.schemaFileName))))
		if refParam != "" {

			schemaURL += "?ref=" + url.QueryEscape(refParam)
		}

		if s, _, sErr := f.fetchContentBase64(ctx, schemaURL, token); sErr == nil {

			schema = s
		}
	}

	// 3) revision = latest commit sha (fallback: blob sha)
	rev, err := f.fetchLatestCommitSHA(ctx, owner, repoName, fp, refParam, token)
	if err != nil || rev == "" {

		rev = blobSHA
	}

	return values, schema, rev, nil
}

func (f *Fetcher) fetchContentBase64(ctx context.Context, u, token string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {

		return nil, "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.httpClient.Do(req)
	if err != nil {

		return nil, "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		var c contentResp
		if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {

			return nil, "", err
		}

		if strings.ToLower(strings.TrimSpace(c.Encoding)) != "base64" {
			return nil, "", fmt.Errorf("unsupported encoding %q", c.Encoding)
		}

		raw := strings.ReplaceAll(c.Content, "\n", "")

		out, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, "", fmt.Errorf("base64 decode: %w", err)
		}

		return out, c.SHA, nil

	case http.StatusNotFound:
		return nil, "", fmt.Errorf("404 not found: %s", u)
	case http.StatusUnauthorized:
		return nil, "", fmt.Errorf("401 unauthorized")
	case http.StatusForbidden:
		return nil, "", fmt.Errorf("403 forbidden")
	case http.StatusTooManyRequests:
		return nil, "", fmt.Errorf("429 too many requests")
	default:
		return nil, "", fmt.Errorf("%d unexpected", resp.StatusCode)
	}
}

func (f *Fetcher) fetchLatestCommitSHA(ctx context.Context, owner, repo, fp, refParam, token string) (string, error) {
	u := f.apiURL(fmt.Sprintf("/repos/%s/%s/commits", url.PathEscape(owner), url.PathEscape(repo)))
	v := url.Values{}
	v.Set("path", fp)
	v.Set("per_page", "1")

	if strings.TrimSpace(refParam) != "" {

		v.Set("sha", refParam) // branch/tag/SHA pin
	}

	if strings.Contains(u, "?") {

		u += "&" + v.Encode()
	} else {

		u += "?" + v.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {

		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", f.userAgent)

	resp, err := f.httpClient.Do(req)
	if err != nil {

		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		var commits []commitResp
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil {

			return "", err
		}

		if len(commits) > 0 && commits[0].SHA != "" {

			return commits[0].SHA, nil
		}

		return "", nil
	}

	return "", nil // best-effort
}

func (f *Fetcher) apiURL(p string) string {
	return strings.TrimRight(f.baseURL, "/") + p
}

func lastSegment(s string) string {
	s = strings.Trim(s, "/")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {

		return s[i+1:]
	}

	return s
}

func escapePath(pth string) string {
	pth = strings.TrimPrefix(pth, "/")
	if pth == "" {

		return ""
	}

	parts := strings.Split(pth, "/")
	for i := range parts {

		parts[i] = url.PathEscape(parts[i])
	}

	return strings.Join(parts, "/")
}

// payloads
type contentResp struct {
	Type     string `json:"type"`
	Encoding string `json:"encoding"`
	Size     int64  `json:"size"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Content  string `json:"content"`
	SHA      string `json:"sha"`
}

type commitResp struct {
	SHA string `json:"sha"`
}
