package main

import "net/http"

var oscarKeyPair keyPair
var oscarSymKey []byte

func getServerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, struct {
		Key encodableBytes `json:"public_key"`
	}{Key: oscarKeyPair.public})
}
