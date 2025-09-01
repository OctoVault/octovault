package awsps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type Meta struct {
	Version         int64
	Type            string // String | StringList | SecureString
	ARN             string
	LastModified    *time.Time
	LastModifiedStr string
}

type Provider struct {
	client *ssm.Client

	mu    sync.RWMutex
	ttl   time.Duration
	cache map[string]cacheEntry
}

type cacheEntry struct {
	value []byte
	meta  Meta
	exp   time.Time
}

func New(ctx context.Context, region string, ttl time.Duration, optFns ...func(*config.LoadOptions) error) (*Provider, error) {

	var opts []func(*config.LoadOptions) error
	opts = append(opts, optFns...)

	if region != "" {

		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {

		return nil, fmt.Errorf("load aws config: %w", err)
	}

	if ttl <= 0 {

		ttl = time.Minute
	}

	return &Provider{
		client: ssm.NewFromConfig(cfg),
		ttl:    ttl,
		cache:  make(map[string]cacheEntry),
	}, nil
}

func (p *Provider) GetParameter(ctx context.Context, name string, withDecryption bool) ([]byte, Meta, error) {

	if strings.TrimSpace(name) == "" {
		return nil, Meta{}, errors.New("parameter name required")
	}

	now := time.Now()

	// 캐시 조회
	p.mu.RLock()
	if ent, ok := p.cache[name]; ok && ent.exp.After(now) {

		p.mu.RUnlock()

		return ent.value, ent.meta, nil
	}

	p.mu.RUnlock()

	// SSM 호출
	out, err := p.client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(withDecryption),
	})

	if err != nil {

		var nf *ssmtypes.ParameterNotFound
		var iae *ssmtypes.InvalidKeyId

		switch {
		case errors.As(err, &nf):
			return nil, Meta{}, fmt.Errorf("aws ssm: parameter %q not found", name)
		case errors.As(err, &iae):
			return nil, Meta{}, fmt.Errorf("aws ssm: invalid kms key for %q: %v", name, err)
		default:
			return nil, Meta{}, fmt.Errorf("aws ssm: get parameter: %w", err)
		}
	}

	if out.Parameter == nil || out.Parameter.Value == nil {

		return nil, Meta{}, fmt.Errorf("aws ssm: parameter %q has no value", name)
	}

	meta := Meta{
		Version:         aws.ToInt64(&out.Parameter.Version),
		Type:            string(out.Parameter.Type),
		ARN:             aws.ToString(out.Parameter.ARN),
		LastModified:    out.Parameter.LastModifiedDate,
		LastModifiedStr: "",
	}

	val := []byte(aws.ToString(out.Parameter.Value))

	// 캐시 저장
	p.mu.Lock()
	p.cache[name] = cacheEntry{value: val, meta: meta, exp: now.Add(p.ttl)}
	p.mu.Unlock()

	return val, meta, nil
}

func (p *Provider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {

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

	switch t := cur.(type) {
	case string:
		return []byte(t), nil
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return nil, fmt.Errorf("marshal value at %q: %w", jsonKey, err)
		}

		return b, nil
	}
}
