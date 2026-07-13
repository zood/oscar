package main

import (
	"net/http"

	"zood.dev/oscar/encodable"
)

func (api httpAPI) getServerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	pubKey := api.keyPair.Public
	sendSuccess(w, struct {
		Key encodable.Bytes `json:"public_key"`
	}{Key: pubKey})
}
