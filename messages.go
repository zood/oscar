package main

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// a type that can conforms to the json.Marshal and json.Unmarshal interfaces,
// which converts the bytes between []byte and base64
type encodableBytes []byte

func (eb encodableBytes) MarshalJSON() ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(eb)))
	base64.StdEncoding.Encode(dst, eb)
	final := append([]byte(`"`), dst...)
	final = append(final, []byte(`"`)...)
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
	ID                int            `db:"id"json:"id"`
	RecipientID       int64          `db:"recipient_id"json:"-"`
	PublicRecipientID encodableBytes `json:"recipient_id"`
	SenderID          int64          `db:"sender_id"json:"-"`
	PublicSenderID    encodableBytes `json:"sender_id"`
	CipherText        encodableBytes `db:"cipher_text"json:"cipher_text"`
	Nonce             encodableBytes `db:"nonce"json:"nonce"`
	SentDate          int64          `db:"sent_date"json:"sent_date"`
}

// SendMessageToUserHandler handles POST /users/{public_id}/messages
func SendMessageToUserHandler(w http.ResponseWriter, r *http.Request) {
	// make sure this user exists
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	// make sure the caller is legitimate
	ok, sessionUserID := verifySession(w, r)
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
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	// cipherText, err := hex.DecodeString(body.CipherText)
	// if err != nil {
	// 	sendBadReq(w, "unable to decode 'cipher_text' from hexadecimal encoding: "+err.Error())
	// 	return
	// }
	// nonce, err := hex.DecodeString(body.Nonce)
	// if err != nil {
	// 	sendBadReq(w, "unable to decode 'nonce' from hexadecimal encoding: "+err.Error())
	// 	return
	// }

	insertSQL := `
    INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
	_, err = db().Exec(insertSQL, userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

// GetMessagesHandler handles GET /messages
func GetMessagesHandler(w http.ResponseWriter, r *http.Request) {
	ok, sessionUserID := verifySession(w, r)
	if !ok {
		return
	}

	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=?`
	rows, err := db().Queryx(selectSQL, sessionUserID)
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
		msg.PublicRecipientID = pubIDFromUserID(msg.RecipientID)
		msg.PublicSenderID = pubIDFromUserID(msg.SenderID)
		msgs = append(msgs, msg)
	}

	sendSuccess(w, msgs)
}
