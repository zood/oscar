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
	Processed      bool           `db:"processed" json:"processed"`
	// PublicRecipientID encodableBytes `json:"recipient_id"`
}

// sendMessageToUserHandler handles POST /users/{public_id}/messages
func sendMessageToUserHandler(w http.ResponseWriter, r *http.Request) {
	// make sure the caller is legitimate
	ok, sessionUserID := verifySession(w, r)
	if !ok {
		return
	}

	// make sure this user exists
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	if userID == sessionUserID {
		sendBadReq(w, "You can't send a message to yourself")
		return
	}

	body := struct {
		CipherText encodableBytes `json:"cipher_text"`
		Nonce      encodableBytes `json:"nonce"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	insertSQL := `
    INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
	result, err := dbx().Exec(insertSQL, userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)

	go func() {
		msgID, err := result.LastInsertId()
		if err != nil {
			logErr(err)
			return
		}
		pushMessageToUser(msgID, userID)
	}()
}

// getMessagesHandler handles GET /messages
func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	ok, sessionUserID := verifySession(w, r)
	if !ok {
		return
	}

	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=?`
	rows, err := dbx().Queryx(selectSQL, sessionUserID)
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
		// msg.PublicRecipientID = pubIDFromUserID(msg.RecipientID)
		msg.PublicSenderID = pubIDFromUserID(msg.SenderID)
		msgs = append(msgs, msg)
	}

	sendSuccess(w, msgs)
}

func pushMessageToUser(msgID int64, userID int64) {
	selectSQL := `SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE id=?`
	msg := Message{}
	err := dbx().Get(&msg, selectSQL, msgID)
	if err != nil {
		logErr(err)
		return
	}

	// msg.PublicRecipientID = pubIDFromUserID(msg.RecipientID)
	msg.PublicSenderID = pubIDFromUserID(msg.SenderID)

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
		log.Printf("payload: %s", buf)
		sendFirebaseMessage(userID, msgMap)
		return
	}

	// it's too big, so we'll tell the client to sync instead
	sendFirebaseMessage(userID, struct {
		Type      string `json:"type"`
		MessageID string `json:"message_id"`
	}{Type: "message_sync_needed", MessageID: strconv.FormatInt(msgID, 10)})
}

// editMessageHandler handles PUT /messages/{msg_id}/processed
func editMessageHandler(w http.ResponseWriter, r *http.Request) {
	ok, sessionUserID := verifySession(w, r)
	if !ok {
		return
	}

	msgIDStr := mux.Vars(r)["msg_id"]
	msgID, err := strconv.Atoi(msgIDStr)
	if err != nil {
		sendBadReq(w, "message id is not a number")
		return
	}

	// first, check if this message exists and if this user is the recipient
	var foundID, recipientID int64
	err = dbx().QueryRow("SELECT id, recipient_id FROM messages WHERE id=?", msgID).Scan(&foundID, &recipientID)
	if err != nil {
		if err == sql.ErrNoRows {
			// a lie. just don't want to tell them, in case they're not the recipient
			sendBadReq(w, "can't load message")
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	// make sure the caller is the message recipient
	if recipientID != sessionUserID {
		// a lie
		sendBadReq(w, "can't load message")
		return
	}

	_, err = dbx().Exec("UPDATE messages SET processed=1 WHERE id=?", foundID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
