package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"firebase.google.com/go/v4/messaging"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"zood.dev/oscar/encodable"
	"zood.dev/oscar/model"
)

type Message struct {
	ID             int64           `json:"id"`
	RecipientID    int64           `json:"-"`
	SenderID       int64           `json:"-"`
	PublicSenderID encodable.Bytes `json:"sender_id"`
	CipherText     encodable.Bytes `json:"cipher_text"`
	Nonce          encodable.Bytes `json:"nonce"`
	SentDate       int64           `json:"sent_date"`
}

func (api httpAPI) sendMessageToUserHandler(w http.ResponseWriter, r *http.Request) {
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

	providers := providersCtx(r.Context())
	if shouldLogDebug() {
		log.Printf("send_message: %s => %s (urgent? %t, transient? %t)",
			api.db.Username(sessionUserID), api.db.Username(userID),
			body.Urgent, body.Transient)
	}

	kvs := providers.kvs
	msg := Message{}
	msg.CipherText = body.CipherText
	msg.Nonce = body.Nonce
	msg.PublicSenderID, err = kvs.PublicIDFromUserID(sessionUserID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if !body.Transient {
		msg.ID, err = api.db.InsertMessage(userID, sessionUserID, body.CipherText, body.Nonce, time.Now().Unix())
		if err != nil {
			sendInternalErr(w, err)
			return
		}
	}

	sendSuccess(w, nil)

	go func() {
		pushMessageToUser(api.db, api.fcm, msg, userID, body.Urgent)
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

	providers := providersCtx(r.Context())
	db := providers.db
	if shouldLogDebug() {
		log.Debug().Str("username", db.Username(userID)).Int64("messageId", msgID).Msg("get_message")
	}

	rec, err := db.MessageToRecipient(userID, msgID)
	if err != nil {
		sendInternalErr(w, err)
	}

	if rec == nil {
		sendNotFound(w, "Message not found", errorNotFound)
		return
	}

	kvs := providers.kvs
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
	providers := providersCtx(r.Context())
	db := providers.db
	if shouldLogDebug() {
		log.Printf("get_messages: %s", db.Username(userID))
	}

	records, err := db.MessageRecords(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	kvs := providers.kvs
	msgs := make([]Message, 0)
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

	db := providersCtx(r.Context()).db
	if shouldLogDebug() {
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

func pushMessageToUser(db model.Provider, fbClient *messaging.Client, msg Message, userID int64, urgent bool) {
	msgMap := map[string]string{
		"id":          strconv.FormatInt(msg.ID, 10),
		"cipher_text": msg.CipherText.Base64(),
		"nonce":       msg.Nonce.Base64(),
		"sender_id":   msg.PublicSenderID.Base64(),
		"sent_date":   strconv.FormatInt(msg.SentDate, 10),
		"type":        "message_received",
	}

	buf, err := json.Marshal(msgMap)
	if err != nil {
		log.Err(err).Msg("marshaling message map")
		return
	}

	// try to publish it directly via socket
	messagesPubSub.Pub(buf, userID)

	// only bother pushing via FCM or APNS if it's urgent
	if !urgent {
		return
	}

	if len(buf) <= 3584 {
		sendFirebaseMessage(db, fbClient, userID, msgMap, urgent)
		sendAPNSMessage(db, userID, msgMap)
		return
	}

	// It's too big. Has it been persisted, and thus can we send a sync message?
	if msg.ID == 0 {
		log.Error().Msg("encountered a sync message that is transient")
		return
	}

	syncPayload := map[string]string{
		"type":       "message_sync_needed",
		"message_id": strconv.FormatInt(msg.ID, 10),
	}
	sendFirebaseMessage(db, fbClient, userID, syncPayload, urgent)
	sendAPNSMessage(db, userID, syncPayload)
}
