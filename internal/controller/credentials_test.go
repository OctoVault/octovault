package controller

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	corev1 "k8s.io/api/core/v1"
)

func TestTokenFromSecret(t *testing.T) {

	cases := []struct {
		name   string
		data   map[string][]byte
		token  string
		reason string
	}{
		{name: "plain", data: map[string][]byte{"password": []byte("tok")}, token: "tok"},
		{name: "base64", data: map[string][]byte{"password": []byte("dG9r"), "passwordEncoding": []byte("base64")}, token: "tok"},
		{name: "missing", data: map[string][]byte{}, reason: "SecretMissingPassword"},
		{name: "bad base64", data: map[string][]byte{"password": []byte("!!"), "passwordEncoding": []byte("base64")}, reason: "SecretInvalidPasswordEncoding"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := tokenFromSecret(&corev1.Secret{Data: tc.data})
			if tc.reason == "" {

				assert.NoError(t, err)
				assert.Equal(t, tc.token, token)
				return
			}

			assert.Error(t, err)
			assert.Equal(t, tc.reason, tokenFailureReason(err))
			assert.Equal(t, tc.reason == "SecretMissingPassword", errors.Is(err, errMissingPassword))
		})
	}
}
