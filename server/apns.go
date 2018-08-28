package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

var gAPNSP8Path string

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
		return
	}
	var priority int
	if urgent {
		priority = 10
	} else {
		priority = 5
	}
	n := &apns2.Notification{
		Topic:    "io.pijun.michael",
		Priority: priority,
	}
	ap := apsPayload{}
	ap.APS.ContentAvailable = 1
	ap.Data = payload
	n.Payload = ap

	for _, t := range tokens {
		n.DeviceToken = t
		resp, err := apnsClient.Push(n)
		if err != nil {
			log.Printf("Error pushing to user %d with token %s: %v", userID, t, err)
			continue
		}
		if !resp.Sent() {
			if resp.Reason == apns2.ReasonUnregistered {
				// remove the token
				err = rs.DeleteAPNSToken(t)
				if err != nil {
					logErr(err)
				}
			} else {
				err = errors.Errorf("Push to user %d failed because '%s'", userID, resp.Reason)
				logErr(err)
			}
		}
	}

}
