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
)

// tokenFromSecret data.password 를 읽고 passwordEncoding=base64 면 디코딩한다.
// 실패하면 errMissingPassword 또는 errInvalidPasswordEncoding 을 감싼 에러를 반환한다.
func tokenFromSecret(s *corev1.Secret) (string, error) {

	token := secretValue(s, "password")
	if token == "" {

		return "", errMissingPassword
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
	if errors.Is(err, errMissingPassword) {

		return "SecretMissingPassword"
	}

	return "SecretInvalidPasswordEncoding"
}

// secretValue StringData 는 API 서버가 돌려주지 않는 쓰기 전용 필드지만, 테스트에서 쓰는
// fake client 는 Data 로 옮기지 않으므로 함께 본다.
func secretValue(s *corev1.Secret, key string) string {
	if v, ok := s.Data[key]; ok && len(v) > 0 {

		return string(v)
	}

	if v, ok := s.StringData[key]; ok && v != "" {

		return v
	}

	return ""
}
