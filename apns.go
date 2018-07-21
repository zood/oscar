package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func addAPNSTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	body := struct {
		Token string `json:"token"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	if len(body.Token) == 0 {
		sendBadReq(w, "missing 'token' field")
		return
	}

	// check if we already have this token in the db, and that it's associated with this user
	atr, err := rs.APNSToken(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if atr == nil {
		// insert the token, then return
		err = rs.InsertAPNSToken(userID, body.Token)
		if err != nil {
			sendInternalErr(w, err)
		}
		return
	}

	// There was a row in there already.
	// You'd think we could just stop here, but no. :-/ We have to handle
	// the case where a user logs out on their device and somebody else
	// logs in. The device token will still be the same, so we need to make sure
	// the user_id and device token are always in sync.
	if atr.UserID == userID {
		sendSuccess(w, nil)
		return
	}

	err = rs.UpdateUserIDOfAPNSToken(userID, body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}

func deleteAPNSTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	token := mux.Vars(r)["token"]

	err := rs.DeleteAPNSTokenOfUser(userID, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

func sendAPNSMessage(userID int64, payload interface{}, urgent bool) {
	tokens, err := rs.APNSTokensRaw(userID)
	if err != nil {
		logErr(err)
		return
	}

	if len(tokens) == 0 {
		log.Printf("  no APNS tokens for %d", userID)
	}
}
