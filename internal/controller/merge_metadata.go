package controller

import "strings"

var reservedPrefixes = []string{
	"octovault.it/",
	"reconcile.octovault.it/",
	"app.kubernetes.io/",
}

func isReservedKey(k string) bool {

	for _, p := range reservedPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}

	return false
}

func mergeMap(system, user map[string]string) map[string]string {

	result := make(map[string]string)

	for k, v := range user {
		if !isReservedKey(k) {
			result[k] = v
		}
	}

	for k, v := range system {
		result[k] = v
	}

	return result
}

// mergeLabels merges user-defined labels with system labels.
// System labels always take precedence over user-defined labels.
func mergeLabels(system, user map[string]string) map[string]string {
	return mergeMap(system, user)
}

// mergeAnnotations merges user-defined annotations with system annotations.
// System annotations always take precedence over user-defined annotations.
func mergeAnnotations(system, user map[string]string) map[string]string {
	return mergeMap(system, user)
}
