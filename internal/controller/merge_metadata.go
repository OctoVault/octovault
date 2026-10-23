package controller

import (
	"context"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	octovaultv1alpha1 "github.com/octovault/octovault/api/v1alpha1"
)

func mergeMap(system, user map[string]string) map[string]string {

	result := make(map[string]string)

	for k, v := range user {
		if isReservedKey(k) {

			continue
		}

		result[k] = v
	}

	for k, v := range system {
		result[k] = v
	}

	return result
}

// isReservedKey octovault.it 도메인(octovault.it/..., *.octovault.it/...) 키는 컨트롤러 전용이다.
//
// values.yaml 에서 이 키를 넣게 두면 컨트롤러가 내리는 판단을 사용자가 조작할 수 있다.
// 예를 들어 octovault.it/retained-from 은 대상을 누가 다시 가져갈지 정하고,
// octovault.it/repository=true 는 대상 Secret 을 자격증명 Secret 캐시에 올린다.
func isReservedKey(k string) bool {

	prefix, _, found := strings.Cut(k, "/")
	if !found {

		return false
	}

	return prefix == "octovault.it" || strings.HasSuffix(prefix, ".octovault.it")
}

// mergeLabels merges user-defined labels with system labels.
// System labels always take precedence over user-defined labels.
// User keys in the reserved octovault.it domain are dropped.
func mergeLabels(system, user map[string]string) map[string]string {
	return mergeMap(system, user)
}

// mergeAnnotations merges user-defined annotations with system annotations.
// System annotations always take precedence over user-defined annotations.
// User keys in the reserved octovault.it domain are dropped.
func mergeAnnotations(system, user map[string]string) map[string]string {
	return mergeMap(system, user)
}

// reservedKeysIn values.yaml 의 라벨/어노테이션 중 무시되는 octovault.it 키를 정렬해 돌려준다.
func reservedKeysIn(labels, annotations map[string]string) []string {

	var keys []string
	for _, m := range []map[string]string{labels, annotations} {
		for k := range m {
			if isReservedKey(k) {

				keys = append(keys, k)
			}
		}
	}

	sort.Strings(keys)

	return keys
}

// warnReservedKeys values.yaml 에 무시되는 octovault.it 키가 있으면 로그와 Warning 이벤트로 알린다.
// 같은 OctoVault 의 같은 키 목록은 한 번만 알리고, 키가 사라지면 기록을 지운다.
func (r *OctoVaultReconciler) warnReservedKeys(ctx context.Context, ov *octovaultv1alpha1.OctoVault, doc valuesDoc) {

	uid := string(ov.UID)
	keys := reservedKeysIn(doc.Metadata.Labels, doc.Metadata.Annotations)
	if len(keys) == 0 {

		r.reservedWarned.Delete(uid)
		return
	}

	joined := strings.Join(keys, ",")
	if prev, seen := r.reservedWarned.Swap(uid, joined); seen && prev == joined {

		return
	}

	logf.FromContext(ctx).Info("values.yaml sets keys reserved for the controller; they are ignored", "keys", joined)
	r.Recorder.Eventf(ov, corev1.EventTypeWarning, "ReservedKeysIgnored",
		"values.yaml metadata keys in the octovault.it domain are reserved for the controller and were ignored: %s", joined)
}
