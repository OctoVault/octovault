package controller

import (
	"context"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

// StatusRetryInterval status 기록이 conflict 로 실패했을 때 다시 시도하기까지의 시간.
//
// 실패 상태(예: 토큰 폐기)를 기록하지 못한 채 poll 주기(OctoRepository 10분, OctoVault 5분)를
// 기다리면 그동안 상태가 이전 값(Synced)으로 남아 장애가 가려진다. conflict 는 대부분 바로 다시
// 시도하면 풀리므로 짧게 잡는다.
const StatusRetryInterval = 5 * time.Second

// StatusErrorRetryInterval conflict 가 아닌 status 기록 실패(RBAC 누락, 5xx 등) 뒤 다시 시도하기까지의 시간.
// 곧바로 풀리지 않는 오류라 짧게 두드리지 않는다.
const StatusErrorRetryInterval = time.Minute

// statusWrites reconcile 한 번 동안의 status 기록 실패를 모은다.
//
// status 를 쓰는 헬퍼는 여러 겹으로 호출되고, 각자 "다음 주기에 다시 본다"는 Result 를 돌려준다.
// 기록 실패를 그 모든 반환값에 실어 나르는 대신, reconcile 시작 때 ctx 에 하나 넣어 두고
// 끝날 때 결과를 고친다(apply).
type statusWrites struct {
	err error
}

type statusWritesKey struct{}

func trackStatusWrites(ctx context.Context) (context.Context, *statusWrites) {

	w := &statusWrites{}

	return context.WithValue(ctx, statusWritesKey{}, w), w
}

// noteStatusWriteError status 기록 실패를 남긴다. 추적 중이 아니면 아무것도 하지 않는다.
func noteStatusWriteError(ctx context.Context, err error) {
	if w, ok := ctx.Value(statusWritesKey{}).(*statusWrites); ok && err != nil && w.err == nil {

		w.err = err
	}
}

// apply status 기록이 실패했다면, 다시 보는 시점을 원래보다 앞당긴다(원래 더 이르면 그대로).
//   - conflict: StatusRetryInterval(5s). 대부분 바로 풀린다.
//   - 그 밖의 오류(RBAC 누락, 5xx 등): StatusErrorRetryInterval(1m).
//
// 에러를 반환하지 않는다. 에러를 돌리면 controller-runtime 이 원래의 RequeueAfter 를 버리고
// 밀리초 단위부터 시작하는 지수 백오프로 재시도해, 처음 몇 초 사이에 reconcile(과 그 안의 GitHub/AWS
// 호출)이 수십 번 돌 수 있다. rate limit 대기 중이어도 GitHub 는 다시 부르지 않는다(Fetcher 가 기억한다).
func (w *statusWrites) apply(res ctrl.Result, err error) (ctrl.Result, error) {
	if err != nil || w.err == nil {

		return res, err
	}

	retry := StatusErrorRetryInterval
	if apierrors.IsConflict(w.err) {

		retry = StatusRetryInterval
	}

	if res.RequeueAfter == 0 || res.RequeueAfter > retry {

		res.RequeueAfter = retry
	}

	return res, nil
}
