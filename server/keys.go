package main

import (
	"net/http"

	"zood.dev/oscar/encodable"
)

func getServerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	pubKey := providersCtx(r.Context()).keyPair.Public
	sendSuccess(w, struct {
		Key encodable.Bytes `json:"public_key"`
	}{Key: pubKey})
}
