package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/model"
)

func TestVerifyEmailHandler(t *testing.T) {
	prvdrs := createTestProviders(t)
	handler := newOscarRouter(prvdrs)
	endpoint := "/1/email-verifications"

	assertIsJSON := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		body := map[string]interface{}{}
		err := json.Unmarshal(w.Body.Bytes(), &body)
		require.NoError(t, err, "body should be json")
	}

	t.Run("bad json", func(t *testing.T) {
		body := bytes.NewBuffer([]byte("not json body"))
		req := httptest.NewRequest(http.MethodPost, endpoint, body)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assertIsJSON(t, w)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "unable to parse POST body")
	})

	t.Run("empty token", func(t *testing.T) {
		data := map[string]interface{}{
			"token": "",
		}
		body, err := json.Marshal(data)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assertIsJSON(t, w)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "Missing verification token")
	})

	t.Run("invalid token", func(t *testing.T) {
		data := map[string]interface{}{
			"token": "deadbeef",
		}
		body, err := json.Marshal(data)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assertIsJSON(t, w)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), "22")
	})

	t.Run("successful", func(t *testing.T) {
		token := "some-token"
		email := "example@example.com"
		_, err := prvdrs.db.InsertUser(model.UserRecord{
			Username:                 "jim",
			PublicKey:                []byte("public-key"),
			WrappedSecretKey:         []byte("wrapped-secret-key"),
			WrappedSecretKeyNonce:    []byte("wrapped-secret-key-nonce"),
			WrappedSymmetricKey:      []byte("wrapped-symmetric-key"),
			WrappedSymmetricKeyNonce: []byte("wrapped-symmetric-key-nonce"),
			PasswordSalt:             []byte("password-salt"),
			Email:                    &email,
		}, &token)
		require.NoError(t, err)
		data := map[string]interface{}{
			"token": token,
		}
		body, err := json.Marshal(data)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		assertIsJSON(t, w)
		require.Equal(t, http.StatusOK, w.Code)
		require.Contains(t, w.Body.String(), "{}")
	})
}
