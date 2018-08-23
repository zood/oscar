package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"zood.xyz/oscar/encodable"
)

// a type that conforms to the json.Marshal and json.Unmarshal interfaces,
// which converts the bytes between []byte and base64
// type encodableBytes []byte

// func (eb encodableBytes) MarshalJSON() ([]byte, error) {
// 	dst := make([]byte, base64.StdEncoding.EncodedLen(len(eb)))
// 	base64.StdEncoding.Encode(dst, eb)
// 	final := append([]byte{'"'}, dst...)
// 	final = append(final, '"')
// 	return final, nil
// }

// func (eb *encodableBytes) UnmarshalJSON(data []byte) error {
// 	if len(data) < 2 {
// 		return errors.New("byte data must be encoded as a base64 string")
// 	}
// 	if data[0] != '"' || data[len(data)-1] != '"' {
// 		return errors.New("base64 string must be surrounded by double quotes")
// 	}
// 	encodedData := data[1 : len(data)-1]
// 	decodedData := make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))
// 	l, err := base64.StdEncoding.Decode(decodedData, encodedData)
// 	if err != nil {
// 		return err
// 	}
// 	// with base64, you have to check the length that it ended up being decoded
// 	// into, because the value from DecodedLen() is max, not the exact amount
// 	*eb = decodedData[:l]
// 	return nil
// }

// func (eb encodableBytes) Value() (driver.Value, error) {
// 	return []byte(eb), nil
// }

// Message ...
type Message struct {
	ID             int64           `json:"id"`
	RecipientID    int64           `json:"-"`
	SenderID       int64           `json:"-"`
	PublicSenderID encodable.Bytes `json:"sender_id"`
	CipherText     encodable.Bytes `json:"cipher_text"`
	Nonce          encodable.Bytes `json:"nonce"`
	SentDate       int64           `json:"sent_date"`
}

// sendMessageToUserHandler handles POST /users/{public_id}/messages
func sendMessageToUserHandler(w http.ResponseWriter, r *http.Request) {
	sessionUserID := userIDFromContext(r.Context())

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
		CipherText encodable.Bytes `json:"cipher_text"`
		Nonce      encodable.Bytes `json:"nonce"`
		Urgent     bool            `json:"urgent"`
		Transient  bool            `json:"transient"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to decode body: "+err.Error())
		return
	}

	if shouldLogInfo() {
		log.Printf("send_message: %s => %s (urgent? %t, transient? %t)",
			rs.Username(sessionUserID), rs.Username(userID),
			body.Urgent, body.Transient)
	}

	msg := Message{}
	msg.CipherText = body.CipherText
	msg.Nonce = body.Nonce
	msg.PublicSenderID, err = kvs.PublicIDFromUserID(sessionUserID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if !body.Transient {
		msg.ID, err = rs.InsertMessage(userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
		if err != nil {
			sendInternalErr(w, err)
			return
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

	if shouldLogInfo() {
		log.Printf("get_message: %s %d", rs.Username(userID), msgID)
	}

	rec, err := rs.MessageToRecipient(userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
	}

	if rec == nil {
		sendNotFound(w, "Message not found", errorNotFound)
		return
	}

	pubID, err := kvs.PublicIDFromUserID(rec.SenderID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	msg := Message{
		ID:             rec.ID,
		RecipientID:    rec.RecipientID,
		SenderID:       rec.SenderID,
		CipherText:     rec.CipherText,
		Nonce:          rec.Nonce,
		SentDate:       rec.SentDate,
		PublicSenderID: pubID,
	}

	sendSuccess(w, msg)
}

// getMessagesHandler handles GET /messages
func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogInfo() {
		log.Printf("get_messages: %s", rs.Username(userID))
	}

	records, err := rs.MessageRecords(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	msgs := make([]Message, 0, 0)
	for _, r := range records {
		pubID, err := kvs.PublicIDFromUserID(r.SenderID)
		if err != nil {
			sendInternalErr(w, err)
			return
		}
		msg := Message{
			ID:             r.ID,
			RecipientID:    r.RecipientID,
			SenderID:       r.SenderID,
			CipherText:     r.CipherText,
			Nonce:          r.Nonce,
			SentDate:       r.SentDate,
			PublicSenderID: pubID,
		}
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

	if shouldLogInfo() {
		log.Printf("delete_message: %s %d", rs.Username(userID), msgID)
	}

	// only delete the message if the calling user is also the recipient
	err = rs.DeleteMessageToRecipient(userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

func pushMessageToUser(msg Message, userID int64, urgent bool) {
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

	// NOTE:
	// We should only push messages to iOS if it's urgent, because APNs
	// will throttle us instead of holding on to messages like FCM.

	// if the payload is small, send the entire thing
	if len(buf) <= 3584 {
		sendFirebaseMessage(userID, msgMap, urgent)
		if urgent {
			sendAPNSMessage(userID, msgMap, urgent)
		}
		return
	}

	// it's too big, so we'll tell the client to sync instead
	if msg.ID == 0 {
		logErr(errors.New("unable to send sync message via FCM for transient message"))
		return
	}

	syncPayload := struct {
		Type      string `json:"type"`
		MessageID string `json:"message_id"`
	}{Type: "message_sync_needed", MessageID: strconv.FormatInt(msg.ID, 10)}
	sendFirebaseMessage(userID, syncPayload, urgent)
	if urgent {
		sendAPNSMessage(userID, syncPayload, urgent)
	}
}
