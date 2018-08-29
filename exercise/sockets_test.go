package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"testing"
	"time"

	"zood.xyz/oscar/encodable"

	"github.com/gorilla/websocket"
	"zood.xyz/oscar/sodium"
)

const (
	socketCmdNop     byte = 0
	socketCmdWatch        = 1
	socketCmdIgnore       = 2
	socketCmdMessage      = 3
)

type pushedMessage struct {
	ID         *string         `json:"id,omitempty"`
	CipherText encodable.Bytes `json:"cipher_text"`
	Nonce      encodable.Bytes `json:"nonce"`
	SenderID   encodable.Bytes `json:"sender_id"`
	SentDate   string          `json:"sent_date"`
}

type socketClient struct {
	conn   *websocket.Conn
	finish chan bool
	inbox  <-chan []byte
	outbox chan<- []byte
}

func (sc *socketClient) readConn(writableInbox chan []byte, t *testing.T) {
	defer close(writableInbox)
	for {
		msgType, buf, err := sc.conn.ReadMessage()
		if err != nil {
			return
		}
		if msgType != websocket.BinaryMessage {
			t.Fatal("socket received a non-binary message")
		}
		log.Printf("client read: %s", buf[:6])
		writableInbox <- buf
	}
}

func (sc *socketClient) start(t *testing.T) {
	sc.finish = make(chan bool)

	writableInbox := make(chan []byte, 5)
	sc.inbox = writableInbox
	go sc.readConn(writableInbox, t)

	readableOutbox := make(chan []byte, 5)
	sc.outbox = readableOutbox
	go sc.writeConn(readableOutbox, t)
}

func (sc *socketClient) stop() {
	sc.conn.Close()
	close(sc.finish)
}

func (sc *socketClient) writeConn(readableOutbox chan []byte, t *testing.T) {
	defer close(readableOutbox)
	for {
		select {
		case <-sc.finish:
			return
		case msg := <-readableOutbox:
			if msg == nil {
				return
			}
			err := sc.conn.WriteMessage(websocket.BinaryMessage, msg)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestSocketServer(t *testing.T) {
	user := createUserOnServer(t)
	token := login(user, t)

	hdr := make(http.Header)
	hdr.Add("Sec-Websocket-Protocol", token)
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+apiAddress+"/alpha/sockets", hdr)
	if err != nil {
		t.Fatal(err)
	}
	sc := socketClient{conn: conn}
	sc.start(t)

	// make up a drop box address
	boxID := make([]byte, dropBoxIDSize)
	sodium.Random(boxID)

	pkg1 := []byte("Hello, my world!")
	dropPackage(pkg1, boxID, token, t)

	// send a watch command for that box
	sc.outbox <- append([]byte{socketCmdWatch}, boxID...)

	// we should get a box notification message back on the socket
	select {
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not receive box notification back in time")
	case rcvdPkg := <-sc.inbox:
		shouldBe := append([]byte{socketCmdWatch}, boxID...)
		shouldBe = append(shouldBe, pkg1...)
		if !bytes.Equal(rcvdPkg, shouldBe) {
			t.Fatal("Received package did not match expected")
		}
	}

	// create another user to send us a message, so we receive it over the socket
	otherUser := createUserOnServer(t)
	otherToken := login(otherUser, t)
	msg := outboundMessage{
		CipherText: []byte("some cipher text"),
		Nonce:      []byte("some nonce"),
		Urgent:     true,
		Transient:  true,
	}
	sendMessage(msg, user.publicID, otherToken, t)

	// Our next notification on the socket should be a message from the other user.
	select {
	case <-time.After(200 * time.Millisecond):
		t.Fatal("did not receive the message notification in time")
	case rcvdMsgBytes := <-sc.inbox:
		// log.Printf("rcvdMsg: %s", rcvdMsgBytes)
		if len(rcvdMsgBytes) < 2 {
			t.Fatal("message is too short")
		}
		if rcvdMsgBytes[0] != socketCmdMessage {
			t.Fatalf("Incorrect/missing command prefix. Found prefix %d", rcvdMsgBytes[0])
		}
		pMsg := pushedMessage{}
		if err = json.Unmarshal(rcvdMsgBytes[1:], &pMsg); err != nil {
			t.Fatal(err)
		}
		// validate all the fields
		// It was a transient message, so the id should be nil
		if pMsg.ID != nil && *pMsg.ID != "0" {
			t.Fatalf("Expecting a nil/0 message id, but found %s", *pMsg.ID)
		}
		if !bytes.Equal(pMsg.CipherText, msg.CipherText) {
			t.Fatal("Cipher text doesn't match")
		}
		if !bytes.Equal(pMsg.Nonce, msg.Nonce) {
			t.Fatal("Nonce doesn't match")
		}
		if !bytes.Equal(pMsg.SenderID, otherUser.publicID) {
			t.Fatal("Sender id is incorrect")
		}
	}

	sc.stop()
}
