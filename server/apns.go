package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
	"zood.dev/oscar/model"
)

var apnsClient *apns2.Client

type apsPayload struct {
	APS struct {
		ContentAvailable int `json:"content-available"`
	} `json:"aps"`
	Data interface{} `json:"data"`
}

func createAPNSClient(p8Path, keyID, teamID string, production bool) error {
	key, err := token.AuthKeyFromFile(p8Path)
	if err != nil {
		return err
	}
	token := &token.Token{
		AuthKey: key,
		KeyID:   keyID,
		TeamID:  teamID,
	}

	apnsClient = apns2.NewTokenClient(token)
	if production {
		apnsClient.Production()
	} else {
		apnsClient.Development()
	}

	return nil
}

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
	db := providersCtx(r.Context()).db
	atr, err := db.APNSToken(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if atr == nil {
		// insert the token, then return
		err = db.InsertAPNSToken(userID, body.Token)
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

	err = db.UpdateUserIDOfAPNSToken(userID, body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}

func deleteAPNSTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	token := mux.Vars(r)["token"]

	db := providersCtx(r.Context()).db
	err := db.DeleteAPNSTokenOfUser(userID, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

func sendAPNSMessage(db model.Provider, userID int64, payload interface{}) {
	tokens, err := db.APNSTokensRaw(userID)
	if err != nil {
		log.Err(err).Msg("db.APNSTokensRaw")
		return
	}

	if len(tokens) == 0 {
		return
	}
	n := &apns2.Notification{
		Topic:    "xyz.zood.michael",
		Priority: 5,
		PushType: apns2.PushTypeBackground,
	}
	ap := apsPayload{}
	ap.APS.ContentAvailable = 1
	ap.Data = payload
	n.Payload = ap

	for _, t := range tokens {
		n.DeviceToken = t
		resp, err := apnsClient.Push(n)
		if err != nil {
			log.Err(err).Int64("userId", userID).Str("token", t).Msg("pushing to APNS user")
			continue
		}
		if !resp.Sent() {
			if resp.Reason == apns2.ReasonUnregistered || resp.Reason == apns2.ReasonBadDeviceToken {
				// remove the token
				err = db.DeleteAPNSToken(t)
				if err != nil {
					log.Err(err).Msg("deleting an apns token")
				}
			} else {
				log.Error().Int64("userId", userID).Str("reason", resp.Reason).Msg("APNS push failure reason")
			}
		}
	}
}
