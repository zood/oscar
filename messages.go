package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// a type that can conforms to the json.Marshal and json.Unmarshal interfaces,
// which serializes the bytes to a hexadecimal string
type hexableBytes []byte

func (hb hexableBytes) MarshalJSON() ([]byte, error) {
	dst := make([]byte, hex.EncodedLen(len(hb)))
	hex.Encode(dst, hb)
	final := append([]byte(`"`), dst...)
	final = append(final, []byte(`"`)...)
	return final, nil
}

func (hb *hexableBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return errors.New("byte data must be encoded as a hexadecimal encoded string")
	}
	if data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("hexadecimal encoded string must be surrounded by double quotes")
	}
	hexData := data[1 : len(data)-1]
	*hb = make([]byte, hex.DecodedLen(len(hexData)))
	_, err := hex.Decode(*hb, hexData)
	return err
}

// Message ...
type Message struct {
	ID          int          `db:"id"json:"id"`
	RecipientID int          `db:"recipient_id"json:"recipient_id"`
	SenderID    int          `db:"sender_id"json:"sender_id"`
	CipherText  hexableBytes `db:"cipher_text"json:"cipher_text"`
	Nonce       hexableBytes `db:"nonce"json:"nonce"`
	SentDate    int64        `db:"sent_date"json:"sent_date"`
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
		CipherText string `json:"cipher_text"`
		Nonce      string `json:"nonce"`
	}{}
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	cipherText, err := hex.DecodeString(body.CipherText)
	if err != nil {
		sendBadReq(w, "unable to decode 'cipher_text' from hexadecimal encoding: "+err.Error())
		return
	}
	nonce, err := hex.DecodeString(body.Nonce)
	if err != nil {
		sendBadReq(w, "unable to decode 'nonce' from hexadecimal encoding: "+err.Error())
		return
	}

	insertSQL := `
    INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
	_, err = db().Exec(insertSQL, userID, sessionUserID, cipherText, nonce, time.Now().Unix())
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
		msgs = append(msgs, msg)
	}

	sendSuccess(w, msgs)
}
