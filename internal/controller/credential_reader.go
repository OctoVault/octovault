package controller

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getCredentialSecret 자격증명 Secret 을 먼저 캐시에서 찾고, 없으면 API 서버에서 읽는다.
//
// manager client 는 Secret 을 캐시하지 않으므로(대상 Secret 데이터를 비교해야 해서) 그대로 쓰면
// OctoVault 마다 poll 할 때 GET 이 나간다. 자격증명 Secret 은 octovault.it/repository 라벨이
// 붙어 있으면 라벨로 범위를 좁힌 캐시에 이미 있으므로 그쪽을 먼저 본다. 라벨이 없으면
// 캐시에 없으니 API 서버로 넘어간다. cached 가 nil 이면 바로 direct 를 쓴다.
func getCredentialSecret(ctx context.Context, cached, direct client.Reader, key types.NamespacedName, out *corev1.Secret) error {
	if cached != nil {
		if err := cached.Get(ctx, key, out); !apierrors.IsNotFound(err) {

			return err
		}
	}

	return direct.Get(ctx, key, out)
}
