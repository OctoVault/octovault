package controller

import (
	"context"
	"fmt"
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

// apply status 기록이 실패했다면 reconcile 결과를 고친다.
//   - conflict: StatusRetryInterval 뒤에 다시 본다(원래 더 이르면 그대로).
//   - 그 밖의 오류(RBAC 누락 등): 에러를 돌려 controller-runtime 의 지수 백오프를 탄다.
//     고정 간격으로 계속 두드리지 않는다.
func (w *statusWrites) apply(res ctrl.Result, err error) (ctrl.Result, error) {
	if err != nil || w.err == nil {

		return res, err
	}

	if !apierrors.IsConflict(w.err) {

		return ctrl.Result{}, fmt.Errorf("status update failed: %w", w.err)
	}

	if res.RequeueAfter == 0 || res.RequeueAfter > StatusRetryInterval {

		res.RequeueAfter = StatusRetryInterval
	}

	return res, nil
}
