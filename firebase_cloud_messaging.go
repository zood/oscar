package main

import (
	"bytes"
	"database/sql"
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
	if shouldLogInfo() {
		log.Printf("sending fcm to %s", usernameFromID(userID))
	}
	rows, err := db().Query("SELECT token FROM user_fcm_tokens WHERE user_id=?", userID)
	if err != nil {
		logErr(err)
		return
	}

	var tokens []string
	for rows.Next() {
		var t string
		err = rows.Scan(&t)
		if err != nil {
			logErr(err)
		}
		tokens = append(tokens, t)
	}

	if len(tokens) == 0 {
		log.Printf("  no tokens for %d", userID)
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
			var foundID int64
			// check if we already have the canonical token for this user
			err := dbx().Get(&foundID, "SELECT id FROM user_fcm_tokens WHERE user_id=? AND token=?", userID, result.RegistrationID)
			if err == nil {
				// we do, so drop the row with the old token
				_, err := dbx().Exec("DELETE FROM user_fcm_tokens WHERE token=?", tokens[i])
				if err != nil {
					logErr(err)
				}
			} else if err == sql.ErrNoRows {
				// nope, we don't. So replace the old token.
				changes, err := db().Exec("UPDATE user_fcm_tokens SET token=? WHERE token=?", result.RegistrationID, tokens[i])
				if err != nil {
					logErr(err)
				} else {
					cnt, err := changes.RowsAffected()
					if err != nil {
						logErr(err)
					} else {
						if cnt != 1 {
							logErr(fmt.Errorf("received a registration id change, but no %d rows affected in db change\nmessage_id: %s\nregistration_id: %s\nuser id: %d\ntoken: %s", cnt, *result.MessageID, *result.RegistrationID, userID, tokens[i]))
						}
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
				db().Exec("DELETE FROM user_fcm_tokens WHERE token=?", tokens[i])
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
	var foundID, foundUserID int64
	selectSQL := `SELECT id, user_id FROM user_fcm_tokens WHERE token=?`
	err = dbx().QueryRow(selectSQL, body.Token).Scan(&foundID, &foundUserID)
	if err != nil {
		if err == sql.ErrNoRows {
			// insert the token, then return
			_, err = dbx().Exec("INSERT INTO user_fcm_tokens (user_id, token) VALUES (?, ?)", userID, body.Token)
			if err != nil {
				sendInternalErr(w, err)
			} else {
				sendSuccess(w, nil)
			}
			return
		}
		sendInternalErr(w, err)
		return
	}

	// There was a row in there already.
	// You'd think we could just stop here, but no. :-/ We have to handle
	// the case where a user logs out on their device and somebody else
	// logs in. The device token will still be the same, so we need to make sure
	// the user_id and device token are always in sync.
	if foundUserID == userID {
		sendSuccess(w, nil)
		return
	}

	_, err = dbx().Exec("UPDATE user_fcm_tokens SET user_id=? WHERE token=?", userID, body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}

func deleteFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	token := mux.Vars(r)["token"]

	_, err := dbx().Exec("DELETE FROM user_fcm_tokens WHERE user_id=? AND token=?", userID, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
