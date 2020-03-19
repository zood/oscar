package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestDropPackageHandler(t *testing.T) {
	p := createTestProviders(t)
	dropBoxID := make([]byte, dropBoxIDSize)
	_, err := rand.Read(dropBoxID)
	require.NoError(t, err)

	pkg := []byte("some data to put in the box")
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(pkg))
	r = mux.SetURLVars(r, map[string]string{"box_id": hex.EncodeToString(dropBoxID)})
	ctx := context.WithValue(r.Context(), contextServerProvidersKey, p)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	dropPackageHandler(w, r)

	require.Equal(t, http.StatusOK, w.Code, "Got: %s", w.Body.String())

	// make sure the package is there
	actualPkg, err := p.kvs.PickUpPackage(dropBoxID)
	require.NoError(t, err)
	require.Equal(t, pkg, actualPkg)
}
