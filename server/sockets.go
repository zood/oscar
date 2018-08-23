package main

import (
	"log"
	"net/http"
)

func createSocketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("headers: %+v", r.Header)

	// check the 'Sec-Websocket-Protocol' header for an access token
	token := r.Header.Get("Sec-Websocket-Protocol")
	userID, err := verifyAccessToken(token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if userID == 0 {
		log.Printf("not a known user")
		sendInvalidAccessToken(w)
		return
	}

	log.Printf("This user %d", userID)
}
