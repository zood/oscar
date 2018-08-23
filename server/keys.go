package main

import (
	"net/http"

	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/sodium"
)

var oscarKeyPair sodium.KeyPair
var oscarSymKey []byte

func getServerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, struct {
		Key encodable.Bytes `json:"public_key"`
	}{Key: oscarKeyPair.Public})
}
