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
	"zood.xyz/oscar/relstor"
)

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

	db := database(r.Context())
	if shouldLogInfo() {
		log.Printf("send_message: %s => %s (urgent? %t, transient? %t)",
			db.Username(sessionUserID), db.Username(userID),
			body.Urgent, body.Transient)
	}

	kvs := keyValueStorage(r.Context())
	msg := Message{}
	msg.CipherText = body.CipherText
	msg.Nonce = body.Nonce
	msg.PublicSenderID, err = kvs.PublicIDFromUserID(sessionUserID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if !body.Transient {
		msg.ID, err = db.InsertMessage(userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
		if err != nil {
			sendInternalErr(w, err)
			return
		}
	}

	sendSuccess(w, nil)

	go func() {
		pushMessageToUser(db, msg, userID, body.Urgent)
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

	db := database(r.Context())
	if shouldLogInfo() {
		log.Printf("get_message: %s %d", db.Username(userID), msgID)
	}

	rec, err := db.MessageToRecipient(userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
	}

	if rec == nil {
		sendNotFound(w, "Message not found", errorNotFound)
		return
	}

	kvs := keyValueStorage(r.Context())
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
	db := database(r.Context())
	if shouldLogInfo() {
		log.Printf("get_messages: %s", db.Username(userID))
	}

	records, err := db.MessageRecords(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	kvs := keyValueStorage(r.Context())
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

	db := database(r.Context())
	if shouldLogInfo() {
		log.Printf("delete_message: %s %d", db.Username(userID), msgID)
	}

	// only delete the message if the calling user is also the recipient
	err = db.DeleteMessageToRecipient(userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

func pushMessageToUser(db relstor.Provider, msg Message, userID int64, urgent bool) {
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

	// try to publish it directly via socket
	messagesPubSub.Pub(buf, userID)

	// only bother pushing via FCM or APNS if it's urgent
	if !urgent {
		return
	}

	if len(buf) <= 3584 {
		sendFirebaseMessage(db, userID, msgMap, urgent)
		sendAPNSMessage(db, userID, msgMap, urgent)
		return
	}

	// It's too big. Has it been persisted, and thus can we send a sync message?
	if msg.ID == 0 {
		logErr(errors.New("unable to send sync message via FCM for transient message"))
		return
	}

	syncPayload := struct {
		Type      string `json:"type"`
		MessageID string `json:"message_id"`
	}{Type: "message_sync_needed", MessageID: strconv.FormatInt(msg.ID, 10)}
	sendFirebaseMessage(db, userID, syncPayload, urgent)
	sendAPNSMessage(db, userID, syncPayload, urgent)
}
