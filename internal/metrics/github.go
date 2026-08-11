package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// GitHub REST API 사용량 관측 지표.
// 컨트롤러가 rate limit에 얼마나 근접했는지 사전에 알 수 있어야 하므로
// 응답 헤더에서 읽은 값을 그대로 노출한다.
var (
	// RateLimitRemaining 현재 윈도우에서 남은 요청 수 (X-RateLimit-Remaining)
	RateLimitRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "octovault_github_rate_limit_remaining",
		Help: "Remaining GitHub REST API requests in the current window, per credential.",
	}, []string{"resource", "credential"})

	// RateLimitTotal 윈도우 전체 허용량 (X-RateLimit-Limit)
	RateLimitTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "octovault_github_rate_limit_total",
		Help: "Total GitHub REST API request allowance in the current window, per credential.",
	}, []string{"resource", "credential"})

	// RateLimitResetSeconds 윈도우가 리셋되는 unix timestamp (X-RateLimit-Reset)
	RateLimitResetSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "octovault_github_rate_limit_reset_timestamp_seconds",
		Help: "Unix timestamp at which the GitHub REST API rate limit window resets.",
	}, []string{"resource", "credential"})

	// RequestsTotal 실제로 GitHub에 나간 요청 수를 상태코드별로 집계
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "octovault_github_requests_total",
		Help: "GitHub REST API requests issued by octovault, by endpoint kind and status code.",
	}, []string{"kind", "code"})

	// ConditionalHitsTotal 304 응답 수. rate limit에 카운트되지 않는 요청이므로
	// 이 값이 RequestsTotal 대비 높을수록 캐시가 잘 동작하는 것이다.
	ConditionalHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "octovault_github_conditional_hits_total",
		Help: "GitHub responses served as 304 Not Modified, which do not count against the rate limit.",
	}, []string{"kind"})

	// RateLimitedTotal rate limit 때문에 거절된 요청 수 (403 with remaining=0, 429)
	RateLimitedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "octovault_github_rate_limited_total",
		Help: "GitHub requests rejected because a rate limit was exhausted.",
	}, []string{"kind"})

	// CredentialCheckCacheTotal OctoRepository 자격증명 검증 캐시의 hit/miss
	CredentialCheckCacheTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "octovault_github_credential_check_cache_total",
		Help: "OctoRepository credential verification cache lookups.",
	}, []string{"result"})
)

func init() {
	metrics.Registry.MustRegister(
		RateLimitRemaining,
		RateLimitTotal,
		RateLimitResetSeconds,
		RequestsTotal,
		ConditionalHitsTotal,
		RateLimitedTotal,
		CredentialCheckCacheTotal,
	)
}
