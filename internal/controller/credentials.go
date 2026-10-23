package controller

import (
	"encoding/base64"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// 자격증명 Secret 에서 GitHub 토큰을 읽는 규칙. OctoRepository 와 OctoVault 가 같은 규칙을 써야
// 한쪽만 Failed 가 되는 일이 없다.

var (
	errMissingPassword         = errors.New("missing 'password' key")
	errInvalidPasswordEncoding = errors.New("invalid base64 in 'password' key")

	// errLegacyPasswordEncoding 토큰은 data 로 옮겼지만 base64 표시(passwordEncoding=base64)는 이전 버전의 어노테이션에만 남은 상태.
	// 그대로 쓰면 base64 문자열을 토큰으로 보내 401 만 받으므로, 원인을 알려 주고 멈춘다.
	errLegacyPasswordEncoding = errors.New("passwordEncoding is only set in the octovault.it/passwordEncoding " +
		"annotation, which is no longer read; move it to data.passwordEncoding")
)

// legacyAnnotationKeys 이전 버전이 토큰을 읽던 Secret 어노테이션. 지금은 읽지 않는다.
var legacyAnnotationKeys = []string{"octovault.it/password", "octovault.it/passwordEncoding"}

// tokenFromSecret data.password 를 읽고 passwordEncoding=base64 면 디코딩한다.
// 실패하면 errMissingPassword 또는 errInvalidPasswordEncoding 을 감싼 에러를 반환한다.
func tokenFromSecret(s *corev1.Secret) (string, error) {

	token := secretValue(s, "password")
	if token == "" {

		return "", errMissingPassword
	}

	// 동작을 바꾸는 값은 base64 뿐이다. plain 같은 다른 값이 남아 있으면 지금처럼 그대로 쓰면 된다.
	if secretValue(s, "passwordEncoding") == "" && s.Annotations["octovault.it/passwordEncoding"] == "base64" {

		return "", errLegacyPasswordEncoding
	}

	if secretValue(s, "passwordEncoding") != "base64" {

		return token, nil
	}

	dec, err := base64.StdEncoding.DecodeString(token)
	if err != nil {

		return "", fmt.Errorf("%w: %v", errInvalidPasswordEncoding, err)
	}

	return string(dec), nil
}

// tokenFailureReason tokenFromSecret 실패를 condition reason 으로 바꾼다.
func tokenFailureReason(err error) string {
	switch {
	case errors.Is(err, errMissingPassword):
		return "SecretMissingPassword"
	case errors.Is(err, errLegacyPasswordEncoding):
		return "SecretLegacyAnnotation"
	default:
		return "SecretInvalidPasswordEncoding"
	}
}

// legacyAnnotationHint 토큰이 없을 때 덧붙일 안내. 예전처럼 어노테이션에 넣어 둔 경우 옮기라고 알려 준다.
func legacyAnnotationHint(sec *corev1.Secret) string {
	for _, k := range legacyAnnotationKeys {
		if sec.Annotations[k] != "" {

			return fmt.Sprintf(": annotation %s is no longer read, move the token into the Secret's data "+
				"(data.password, data.passwordEncoding)", k)
		}
	}

	return ""
}

// secretValue Secret data 의 값. 비어 있으면 "".
// stringData 는 쓰기 전용 필드라 API 서버가 읽을 때 돌려주지 않으므로 보지 않는다.
func secretValue(s *corev1.Secret, key string) string {
	if v, ok := s.Data[key]; ok && len(v) > 0 {

		return string(v)
	}

	return ""
}
