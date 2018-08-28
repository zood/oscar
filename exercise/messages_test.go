package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"zood.xyz/oscar/encodable"
)

type outboundMessage struct {
	CipherText encodable.Bytes `json:"cipher_text"`
	Nonce      encodable.Bytes `json:"nonce"`
	Urgent     bool            `json:"urgent"`
	Transient  bool            `json:"transient"`
}

type inboundMessage struct {
	ID         uint64          `json:"id"`
	SenderID   encodable.Bytes `json:"sender_id"`
	CipherText encodable.Bytes `json:"cipher_text"`
	Nonce      encodable.Bytes `json:"nonce"`
	SentDate   int64           `json:"sent_date"`
}

func retrieveMessages(token string, t *testing.T) []inboundMessage {
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/alpha/messages", nil)
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	msgs := make([]inboundMessage, 0)
	if err = json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
		t.Fatal(err)
	}

	return msgs
}

func sendMessage(msg outboundMessage, to []byte, token string, t *testing.T) {
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost,
		apiRoot+"/alpha/users/"+hex.EncodeToString(to)+"/messages",
		bytes.NewReader(msgJSON))
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}
}

func TestMessageTransfers(t *testing.T) {
	userA := createUserOnServer(t)
	tokenA := login(userA, t)
	userB := createUserOnServer(t)
	tokenB := login(userB, t)

	// send a message from A to B
	outMsg := outboundMessage{
		CipherText: []byte("There's plenty of money in the banana stand"),
		Nonce:      []byte("nonce!"),
		Urgent:     false,
		Transient:  false,
	}

	// user A sends to user B
	sendMessage(outMsg, userB.publicID, tokenA, t)

	// user B checks for the message
	msgs := retrieveMessages(tokenB, t)

	if len(msgs) != 1 {
		t.Fatalf("Expecting 1 message. Found %d", len(msgs))
	}
	inMsg := msgs[0]
	if !bytes.Equal(inMsg.CipherText, outMsg.CipherText) {
		t.Fatal("cipher text mismatch")
	}
	if !bytes.Equal(inMsg.Nonce, outMsg.Nonce) {
		t.Fatal("nonce mismatch")
	}
	if !bytes.Equal(inMsg.SenderID, userA.publicID) {
		t.Fatal("incorrect sender id")
	}
	sentDate := time.Unix(inMsg.SentDate, 0)
	if time.Now().Sub(sentDate).Seconds() > 10 {
		t.Fatal("invalid sent_date")
	}

	// user B deletes the message from the server
	req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/alpha/messages/%d", apiRoot, inMsg.ID), nil)
	req.Header.Add("X-Oscar-Access-Token", tokenB)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// retrieve the messages again to make sure that message is deleted
	msgs = retrieveMessages(tokenB, t)
	if len(msgs) != 0 {
		t.Fatalf("The message is still on the server. Num found %d", len(msgs))
	}
}
