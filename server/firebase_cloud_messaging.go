package main

import (
	"context"
	"encoding/json"
	"net/http"

	"firebase.google.com/go/v4/messaging"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"zood.dev/oscar/sqlite"
)

func sendFirebaseMessage(db sqlite.DB, fbClient *messaging.Client, userID int64, payload map[string]string, urgent bool) {
	tokens, err := db.FCMTokensRaw(userID)
	if err != nil {
		log.Err(err).Msg("db.FCMTokensRaw")
		return
	}

	if len(tokens) == 0 {
		return
	}

	cfg := &messaging.AndroidConfig{}
	if urgent {
		cfg.Priority = "high"
	} else {
		cfg.Priority = "normal"
	}

	for _, tk := range tokens {
		_, err = fbClient.Send(context.Background(), &messaging.Message{
			Android: cfg,
			Data:    payload,
			Token:   tk,
		})
		if err != nil {
			if messaging.IsUnregistered(err) {
				// remove the token
				if deleteErr := db.DeleteFCMToken(tk); deleteErr != nil {
					log.Err(deleteErr).Msg("deleting an FCM token")
				}
				continue
			}
			log.Err(err).Msg("sending an FCM message")
		}
	}
}

func (api httpAPI) addFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
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
	ftr, err := api.db.FCMToken(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if ftr == nil {
		// insert the token, then return
		err = api.db.InsertFCMToken(userID, body.Token)
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
	if ftr.UserID == userID {
		sendSuccess(w, nil)
		return
	}

	err = api.db.UpdateUserIDOfFCMToken(userID, body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}

func (api httpAPI) deleteFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	token := mux.Vars(r)["token"]

	err := api.db.DeleteFCMTokenOfUser(userID, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
