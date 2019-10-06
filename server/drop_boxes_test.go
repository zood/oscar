package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDropPackageHandler(t *testing.T) {
	p := createTestProviders(t)
	r := newOscarRouter(p)

	user, kp := createTestUser(t, p)
	token := loginTestUser(t, p, user, kp)

	dropBoxID := make([]byte, dropBoxIDSize)
	_, err := rand.Read(dropBoxID)
	require.NoError(t, err)

	endpoint := fmt.Sprintf("/1/drop-boxes/%s", hex.EncodeToString(dropBoxID))
	pkg := []byte("some data to put in the box")
	req := httptest.NewRequest(http.MethodPut, endpoint, bytes.NewReader(pkg))
	req.Header.Add("X-Oscar-Access-Token", token)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "Got %d: %s", w.Code, w.Body.String())
}
