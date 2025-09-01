package awssm

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
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

type Meta struct {
	VersionID     string
	VersionStages []string
}

type AWSSecretsProvider interface {
	GetSecret(ctx context.Context, name string) (value []byte, meta Meta, err error)
	ExtractJSONKey(value []byte, jsonKey string) (out []byte, err error)
}

type Provider struct {
	client *sm.Client

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
		client: sm.NewFromConfig(cfg),
		ttl:    ttl,
		cache:  make(map[string]cacheEntry),
	}, nil
}

func (p *Provider) GetSecret(ctx context.Context, name string) ([]byte, Meta, error) {

	if name == "" {

		return nil, Meta{}, errors.New("secret name required")
	}

	now := time.Now()
	p.mu.RLock()
	if ent, ok := p.cache[name]; ok && ent.exp.After(now) {

		p.mu.RUnlock()
		return ent.value, ent.meta, nil
	}
	p.mu.RUnlock()

	out, err := p.client.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: aws.String(name)})
	if err != nil {

		var rnfe *types.ResourceNotFoundException
		var ne *types.DecryptionFailure
		var pe *types.InvalidRequestException
		switch {
		case errors.As(err, &rnfe):
			return nil, Meta{}, fmt.Errorf("aws sm: secret %q not found", name)
		case errors.As(err, &ne):
			return nil, Meta{}, fmt.Errorf("aws sm: decryption failure for %q: %v", name, err)
		case errors.As(err, &pe):
			return nil, Meta{}, fmt.Errorf("aws sm: invalid request for %q: %v", name, err)
		default:
			return nil, Meta{}, fmt.Errorf("aws sm: get secret value: %w", err)
		}
	}

	meta := Meta{
		VersionID:     aws.ToString(out.VersionId),
		VersionStages: out.VersionStages,
	}

	var val []byte
	if out.SecretString != nil {

		val = []byte(*out.SecretString)
	} else if out.SecretBinary != nil {

		val = out.SecretBinary
	} else {

		return nil, meta, fmt.Errorf("aws sm: secret %q has neither SecretString nor SecretBinary", name)
	}

	p.mu.Lock()
	p.cache[name] = cacheEntry{value: val, meta: meta, exp: now.Add(p.ttl)}
	p.mu.Unlock()

	return val, meta, nil
}

func (p *Provider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {

	if jsonKey == "" {

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
