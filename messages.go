package main

import (
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// a type that can conforms to the json.Marshal and json.Unmarshal interfaces,
// which converts the bytes between []byte and base64
type encodableBytes []byte

func (eb encodableBytes) MarshalJSON() ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(eb)))
	base64.StdEncoding.Encode(dst, eb)
	final := append([]byte{'"'}, dst...)
	final = append(final, '"')
	return final, nil
}

func (eb *encodableBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return errors.New("byte data must be encoded as a base64 string")
	}
	if data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("base64 string must be surrounded by double quotes")
	}
	encodedData := data[1 : len(data)-1]
	decodedData := make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))
	l, err := base64.StdEncoding.Decode(decodedData, encodedData)
	if err != nil {
		return err
	}
	// with base64, you have to check the length that it ended up being decoded
	// into, because the value from DecodedLen() is max, not the exact amount
	*eb = decodedData[:l]
	return nil
}

func (eb encodableBytes) Value() (driver.Value, error) {
	return []byte(eb), nil
}

// Message ...
type Message struct {
	ID             int64          `db:"id" json:"id"`
	RecipientID    int64          `db:"recipient_id" json:"-"`
	SenderID       int64          `db:"sender_id" json:"-"`
	PublicSenderID encodableBytes `json:"sender_id"`
	CipherText     encodableBytes `db:"cipher_text" json:"cipher_text"`
	Nonce          encodableBytes `db:"nonce" json:"nonce"`
	SentDate       int64          `db:"sent_date" json:"sent_date"`
}

// sendMessageToUserHandler handles POST /users/{public_id}/messages
func sendMessageToUserHandler(w http.ResponseWriter, r *http.Request) {
	sessionUserID := userIDFromContext(r.Context())

	// make sure this user exists
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	if shouldLogInfo() {
		log.Printf("%s => %s", usernameFromID(sessionUserID), usernameFromID(userID))
	}

	if userID == sessionUserID {
		sendBadReq(w, "You can't send a message to yourself")
		return
	}

	body := struct {
		CipherText encodableBytes `json:"cipher_text"`
		Nonce      encodableBytes `json:"nonce"`
		Urgent     bool           `json:"urgent"`
		Transient  bool           `json:"transient"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	msg := Message{}
	msg.CipherText = body.CipherText
	msg.Nonce = body.Nonce
	msg.PublicSenderID = pubIDFromUserID(sessionUserID)

	if !body.Transient {
		insertSQL := `
    INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
		result, err := dbx().Exec(insertSQL, userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
		if err != nil {
			sendInternalErr(w, err)
			return
		}
		msg.ID, err = result.LastInsertId()
		if err != nil {
			logErr(err)
		}
	}

	sendSuccess(w, nil)

	go func() {
		pushMessageToUser(msg, userID, body.Urgent)
	}()
}

// getMessageHandler handles GET /messages/{message_id}
func getMessageHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	vars := mux.Vars(r)
	msgIDStr := vars["message_id"]
	msgID, err := strconv.ParseInt(msgIDStr, 10, 64)
	if err != nil {
		sendBadReq(w, "Invalid message id")
		return
	}

	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=? AND id=?`
	msg := Message{}
	err = dbx().Get(&msg, selectSQL, userID, msgID)
	switch err {
	case nil:
		break
	case sql.ErrNoRows:
		sendNotFound(w, "Message not found", errorNotFound)
		return
	default:
		sendInternalErr(w, err)
		return
	}
	msg.PublicSenderID = pubIDFromUserID(msg.SenderID)

	sendSuccess(w, msg)
}

// getMessagesHandler handles GET /messages
func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=?`
	rows, err := dbx().Queryx(selectSQL, userID)
	if err != nil {
		logErr(err)
		sendInternalErr(w, err)
		return
	}

	msgs := make([]Message, 0, 0)
	for rows.Next() {
		msg := Message{}
		err = rows.StructScan(&msg)
		if err != nil {
			sendInternalErr(w, err)
			return
		}
		msg.PublicSenderID = pubIDFromUserID(msg.SenderID)
		msgs = append(msgs, msg)
	}

	sendSuccess(w, msgs)
}

// handles DELETE /messages/{message_id}
func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	vars := mux.Vars(r)
	msgIDStr := vars["message_id"]
	msgID, err := strconv.ParseInt(msgIDStr, 10, 64)
	if err != nil {
		sendBadReq(w, "Invalid message id")
		return
	}

	// only delete the message if the calling user is also the recipient
	deleteSQL := `DELETE FROM messages WHERE recipient_id=? AND id=?`
	_, err = dbx().Exec(deleteSQL, userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

func pushMessageToUser(msg Message, userID int64, urgent bool) {
	// selectSQL := `SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE id=?`
	// msg := Message{}
	// err := dbx().Get(&msg, selectSQL, msgID)
	// if err != nil {
	// 	logErr(err)
	// 	return
	// }

	msgMap := map[string]interface{}{
		"id":          strconv.FormatInt(msg.ID, 10),
		"cipher_text": msg.CipherText,
		"nonce":       msg.Nonce,
		"sender_id":   msg.PublicSenderID,
		"sent_date":   strconv.FormatInt(msg.SentDate, 10),
		"type":        "message_received",
	}

	buf, err := json.Marshal(msgMap)
	if err != nil {
		logErr(err)
		return
	}

	// if the payload is small, send the entire thing
	if len(buf) <= 3584 {
		sendFirebaseMessage(userID, msgMap, urgent)
		return
	}

	// it's too big, so we'll tell the client to sync instead
	if msg.ID == 0 {
		logErr(errors.New("unable to send sync message via FCM for transient message"))
		return
	}
	sendFirebaseMessage(userID, struct {
		Type      string `json:"type"`
		MessageID string `json:"message_id"`
	}{Type: "message_sync_needed", MessageID: strconv.FormatInt(msg.ID, 10)}, urgent)
}
