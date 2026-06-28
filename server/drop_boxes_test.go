package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestDropPackageHandler(t *testing.T) {
	dropBoxID := make([]byte, dropBoxIDSize)
	rand.Read(dropBoxID)

	pkg := []byte("some data to put in the box")
	r := httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(pkg))
	r = mux.SetURLVars(r, map[string]string{"box_id": hex.EncodeToString(dropBoxID)})

	w := httptest.NewRecorder()
	api := testHTTPAPI(t)
	api.dropPackage(w, r)

	require.Equal(t, http.StatusOK, w.Code, "Got: %s", w.Body.String())

	// make sure the package is there
	actualPkg, err := api.kvs.PickUpPackage(dropBoxID)
	require.NoError(t, err)
	require.Equal(t, pkg, actualPkg)
}
