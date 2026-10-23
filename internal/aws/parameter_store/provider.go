package awsps

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/octovault/octovault/internal/aws/jsonkey"
	"github.com/octovault/octovault/internal/aws/ttlcache"
	ovmetrics "github.com/octovault/octovault/internal/metrics"

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
		client: ssm.NewFromConfig(cfg),
		cache: ttlcache.New(ttl,
			ttlcache.WithMaxEntries[cacheEntry](cache.MaxEntries),
			ttlcache.WithEvictHook[cacheEntry](func(n int) {
				ovmetrics.AWSCacheEvictionsTotal.WithLabelValues("AwsParameterStore").Add(float64(n))
			})),
	}, nil
}

func (p *Provider) GetParameter(ctx context.Context, name string, withDecryption bool) ([]byte, Meta, error) {

	if strings.TrimSpace(name) == "" {
		return nil, Meta{}, errors.New("parameter name required")
	}

	// 복호화 여부에 따라 응답 값이 달라지므로(SecureString 은 암호문/평문) 캐시 키에 포함한다.
	ent, err := p.cache.Get(ctx, cacheKey(name, withDecryption), func(ctx context.Context) (cacheEntry, error) {
		return p.fetch(ctx, name, withDecryption)
	})
	if err != nil {

		return nil, Meta{}, err
	}

	return ent.value, ent.meta, nil
}

func (p *Provider) fetch(ctx context.Context, name string, withDecryption bool) (cacheEntry, error) {

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
			return cacheEntry{}, fmt.Errorf("aws ssm: parameter %q not found", name)
		case errors.As(err, &iae):
			return cacheEntry{}, fmt.Errorf("aws ssm: invalid kms key for %q: %v", name, err)
		default:
			return cacheEntry{}, fmt.Errorf("aws ssm: get parameter: %w", err)
		}
	}

	if out.Parameter == nil || out.Parameter.Value == nil {

		return cacheEntry{}, fmt.Errorf("aws ssm: parameter %q has no value", name)
	}

	meta := Meta{
		Version:         aws.ToInt64(&out.Parameter.Version),
		Type:            string(out.Parameter.Type),
		ARN:             aws.ToString(out.Parameter.ARN),
		LastModified:    out.Parameter.LastModifiedDate,
		LastModifiedStr: "",
	}

	return cacheEntry{value: []byte(aws.ToString(out.Parameter.Value)), meta: meta}, nil
}

func cacheKey(name string, withDecryption bool) string {
	return fmt.Sprintf("%s\x00%t", name, withDecryption)
}

func (p *Provider) ExtractJSONKey(value []byte, jsonKey string) ([]byte, error) {
	return jsonkey.Extract(value, jsonKey)
}
