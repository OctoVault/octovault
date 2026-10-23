package awssm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/octovault/octovault/internal/aws/jsonkey"
	"github.com/octovault/octovault/internal/aws/ttlcache"
	ovmetrics "github.com/octovault/octovault/internal/metrics"

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
	cache  *ttlcache.Cache[cacheEntry]
}

type cacheEntry struct {
	value []byte
	meta  Meta
}

// CacheOptions 조회 결과 캐시 설정.
type CacheOptions struct {
	// TTL 0 이하면 1분.
	TTL time.Duration

	// MaxEntries 0 이하면 ttlcache.DefaultMaxEntries.
	MaxEntries int
}

func New(ctx context.Context, region string, cache CacheOptions, optFns ...func(*config.LoadOptions) error) (*Provider, error) {

	var opts []func(*config.LoadOptions) error
	opts = append(opts, optFns...)

	if region != "" {

		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {

		return nil, fmt.Errorf("load aws config: %w", err)
	}

	ttl := cache.TTL
	if ttl <= 0 {

		ttl = time.Minute
	}

	return &Provider{
		client: sm.NewFromConfig(cfg),
		cache: ttlcache.New(ttl,
			ttlcache.WithMaxEntries[cacheEntry](cache.MaxEntries),
			ttlcache.WithEvictHook[cacheEntry](func(n int) {
				ovmetrics.AWSCacheEvictionsTotal.WithLabelValues("AwsSecretsManager").Add(float64(n))
			})),
	}, nil
}

func (p *Provider) GetSecret(ctx context.Context, name string) ([]byte, Meta, error) {

	if name == "" {

		return nil, Meta{}, errors.New("secret name required")
	}

	ent, err := p.cache.Get(ctx, name, func(ctx context.Context) (cacheEntry, error) {
		return p.fetch(ctx, name)
	})
	if err != nil {

		return nil, ent.meta, err
	}

	return ent.value, ent.meta, nil
}

func (p *Provider) fetch(ctx context.Context, name string) (cacheEntry, error) {

	out, err := p.client.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: aws.String(name)})
	if err != nil {

		var rnfe *types.ResourceNotFoundException
		var ne *types.DecryptionFailure
		var pe *types.InvalidRequestException
		switch {
		case errors.As(err, &rnfe):
			return cacheEntry{}, fmt.Errorf("aws sm: secret %q not found", name)
		case errors.As(err, &ne):
			return cacheEntry{}, fmt.Errorf("aws sm: decryption failure for %q: %v", name, err)
		case errors.As(err, &pe):
			return cacheEntry{}, fmt.Errorf("aws sm: invalid request for %q: %v", name, err)
		default:
			return cacheEntry{}, fmt.Errorf("aws sm: get secret value: %w", err)
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

		return cacheEntry{meta: meta}, fmt.Errorf("aws sm: secret %q has neither SecretString nor SecretBinary", name)
	}

	return cacheEntry{value: val, meta: meta}, nil
}

func (p *Provider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {
	return jsonkey.Extract(value, jsonKey)
}
