package controller

import "strings"

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
