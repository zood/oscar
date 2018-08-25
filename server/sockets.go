package main

import (
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"zood.xyz/oscar/internal/pubsub"
)

const (
	socketCmdNop    byte = 0
	socketCmdWatch       = 1
	socketCmdIgnore      = 2
)

var socketsPubSub = pubsub.NewInt64()

type socketServer struct {
	conn     *websocket.Conn
	closed   chan bool
	messages chan []byte
	userID   int64
	msgSub   chan []byte
}

func (ss socketServer) ignoreBox(boxID []byte) {
}

func (ss socketServer) readConn() {
	defer close(ss.closed) // unblocks the goroutine that's running stop()

	for {
		msgType, buf, err := ss.conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType != websocket.BinaryMessage {
			log.Printf("received a non-binary message")
			break
		}
		if len(buf) == 0 {
			log.Printf("received an invalid length message")
			continue
		}
		switch buf[0] {
		case socketCmdNop:
		case socketCmdWatch:
			ss.watchBox(buf[1:])
		case socketCmdIgnore:
			ss.ignoreBox(buf[1:])
		default:
			log.Printf("unknown socket command: %d", buf[0])
		}
	}
}

func (ss socketServer) start() {
	ss.msgSub = socketsPubSub.Sub(ss.userID)
	go ss.readConn()
}

func (ss socketServer) watchBox(boxID []byte) {
	if len(boxID) != dropBoxIDSize {
		log.Printf("invalid drop box id length (%d)", len(boxID))
		return
	}
}

// Continuously writes any messages from the channel to the socket
func (ss socketServer) writeConn() {
	for msg := range ss.messages {
		if err := ss.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
			break
		}
	}
}

func newSocketServer(conn *websocket.Conn, userID int64) socketServer {
	return socketServer{
		conn:   conn,
		closed: make(chan bool),
		userID: userID,
	}
}

func createSocketHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("headers: %+v", r.Header)

	// check the 'Sec-Websocket-Protocol' header for an access token
	token := r.Header.Get("Sec-Websocket-Protocol")
	userID, err := verifyAccessToken(token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if userID == 0 {
		log.Printf("not a known user")
		sendInvalidAccessToken(w)
		return
	}
	log.Printf("This user %d", userID)

	upgrade := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	conn, err := upgrade.Upgrade(w, r, nil)
	if err != nil {
		// we don't need to do anything. The upgrader sends 400 on our behalf.
		return
	}

	ss := newSocketServer(conn, userID)
	ss.start()
}
