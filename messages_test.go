package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

var testMessage = Message{
	ID:          1,
	RecipientID: 2,
	SenderID:    3,
	CipherText:  []byte("hello, world"),
	Nonce:       []byte("goodbye, bob"),
	SentDate:    time.Now().Unix(),
}
var marshaledMessage []byte

func TestMessageMarshaling(t *testing.T) {
	var err error
	marshaledMessage, err = json.MarshalIndent(testMessage, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", marshaledMessage)
}

func TestMessageUnmarshaling(t *testing.T) {
	// fmt.Printf("unmarshalling %s\n", marshaledMessage)
	msg := Message{}
	err := json.Unmarshal(marshaledMessage, &msg)
	if err != nil {
		t.Fatal(err)
	}

	if testMessage.ID != msg.ID {
		t.Fatal("ids not equal")
	}
	if testMessage.RecipientID != msg.RecipientID {
		t.Fatal("recipient id not equal")
	}
	if testMessage.SenderID != msg.SenderID {
		t.Fatal("sender id not equal")
	}
	if !bytes.Equal(testMessage.CipherText, msg.CipherText) {
		t.Fatalf("cipher text not equal %v\n%v", testMessage.CipherText, msg.CipherText)
	}
	if !bytes.Equal(testMessage.Nonce, msg.Nonce) {
		t.Fatal("nonce not equal")
	}
	if testMessage.SentDate != msg.SentDate {
		t.Fatal("sent date not equal")
	}
}
