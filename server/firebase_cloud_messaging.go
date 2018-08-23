package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

var gFCMServerKey string

type fcmResult struct {
	MessageID      *string `json:"message_id,omitempty"`
	Error          *string `json:"error,omitempty"`
	RegistrationID *string `json:"registration_id,omitempty"`
}

func (r fcmResult) String() string {
	buf, err := json.Marshal(r)
	if err != nil {
		return "err marshalling gcmresult: " + err.Error()
	}
	return string(buf)
}

type fcmResponse struct {
	MulticastID  int64       `json:"multicast_id"`
	Success      int         `json:"success"`
	Failure      int         `json:"failure"`
	CanonicalIDs int         `json:"canonical_ids"`
	Results      []fcmResult `json:"results"`
}

type fcmUnicastMessage struct {
	To       string      `json:"to"`
	Priority string      `json:"priority,omitempty"`
	Data     interface{} `json:"data"`
}

type fcmMulticastMessage struct {
	Tokens   []string    `json:"registration_ids"`
	Priority string      `json:"priority,omitempty"`
	Data     interface{} `json:"data"`
}

func sendFirebaseMessage(userID int64, payload interface{}, urgent bool) {
	tokens, err := rs.FCMTokensRaw(userID)
	if err != nil {
		logErr(err)
		return
	}

	if len(tokens) == 0 {
		return
	}
	priority := ""
	if urgent {
		priority = "high"
	} else {
		priority = "normal"
	}
	var msg interface{}
	if len(tokens) == 1 {
		msg = fcmUnicastMessage{
			To:       tokens[0],
			Priority: priority,
			Data:     payload,
		}
	} else {
		msg = fcmMulticastMessage{
			Tokens:   tokens,
			Priority: priority,
			Data:     payload,
		}
	}

	msgBytes, _ := json.Marshal(msg)
	msgReader := bytes.NewReader(msgBytes)
	req, err := http.NewRequest(
		"POST",
		"https://fcm.googleapis.com/fcm/send",
		msgReader)
	if err != nil {
		logErr(err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "key="+gFCMServerKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logErr(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf, _ := ioutil.ReadAll(resp.Body)
		err = fmt.Errorf("status code %d\nheaders:\n%v\n\nresponse:\n%s", resp.StatusCode, resp.Header, string(buf))
		logErr(err)
		return
	}

	fcmBody := &fcmResponse{}
	err = json.NewDecoder(resp.Body).Decode(fcmBody)
	if err != nil {
		logErr(err)
		return
	}

	// if everything went smoothly, we're done
	if fcmBody.Failure == 0 && fcmBody.CanonicalIDs == 0 {
		if shouldLogDebug() {
			log.Printf("msg id %s", *fcmBody.Results[0].MessageID)
		}
		return
	}

	log.Printf("fcm send was less than normal")

	// let's find out what went wrong
	for i, result := range fcmBody.Results {
		if result.MessageID != nil && result.RegistrationID != nil {
			// We've been provided a canonical registration id. Check if we
			// already have that ID. If so, just drop the old token. If not,
			// update the old token to the new one.
			log.Printf("| MessageID: %v, RegID: %v", result.MessageID, result.RegistrationID)
			// check if we already have the canonical token for this user
			tokRec, err := rs.FCMTokenUser(userID, *result.RegistrationID)
			if err == nil && tokRec != nil {
				// we do, so drop the row with the old token
				err := rs.DeleteFCMToken(tokens[i])
				if err != nil {
					logErr(err)
				}
			} else if err == nil {
				// nope, we don't. So replace the old token.
				rowsAffected, err := rs.ReplaceFCMToken(tokens[i], *result.RegistrationID)
				if err != nil {
					logErr(err)
				} else {
					if rowsAffected != 1 {
						logErr(fmt.Errorf("received a registration id change, but no %d rows affected in db change\nmessage_id: %s\nregistration_id: %s\nuser id: %d\ntoken: %s",
							rowsAffected,
							*result.MessageID,
							*result.RegistrationID,
							userID,
							tokens[i]))
					}
				}
			}
			continue
		}

		if result.Error != nil {
			switch *result.Error {
			case "Unavailable":
				// TODO: retry request
			case "InvalidRegistration":
				fallthrough
			case "NotRegistered":
				// remove the token
				rs.DeleteFCMToken(tokens[i])
			default:
				logErr(fmt.Errorf("error sending via fcm: %s\nuser id: %d", *result.Error, userID))
			}
		}
	}
}

func addFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
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
	ftr, err := rs.FCMToken(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if ftr == nil {
		// insert the token, then return
		err = rs.InsertFCMToken(userID, body.Token)
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

	err = rs.UpdateUserIDOfFCMToken(userID, body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}

func deleteFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	token := mux.Vars(r)["token"]

	err := rs.DeleteFCMTokenOfUser(userID, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
