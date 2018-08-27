package main

import (
	"encoding/hex"
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
	pkgs     chan []byte
	pkgSubs  map[string]chan []byte
	userID   int64
}

func (ss socketServer) ignoreBox(boxID []byte) {
	hexID := hex.EncodeToString(boxID)
	sub := ss.pkgSubs[hexID]
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
	ss.messages = socketsPubSub.Sub(ss.userID)
	go ss.readConn()
	go ss.writeConn()
}

func (ss socketServer) stop() {
	// wait here until someone tells us to shut down
	<-ss.closed

	for hexBoxID, sub := range ss.pkgSubs {
		dropBoxPubSub.Unsub(sub, hexBoxID)
	}

	ss.conn.Close()

}

func (ss socketServer) watchBox(boxID []byte) {
	if len(boxID) != dropBoxIDSize {
		log.Printf("invalid drop box id length (%d)", len(boxID))
		return
	}
	hexID := hex.EncodeToString(boxID)

	// if there's already a sub for this id, skip it
	if ss.pkgSubs[hexID] != nil {
		return
	}

	// create a subscription
	sub := dropBoxPubSub.Sub(hexID)
	ss.pkgSubs[hexID] = sub

	// If there's already a package in the dropbox, send it
	tmp, err := kvs.PickUpPackage(boxID)
	if err != nil {
		logErr(err)
	}
	if len(tmp) > 0 {
		sub <- tmp
	}

	go func() {
		for {
			select {
			case <-ss.closed:
				return
			case pkg := <-sub:
				if pkg == nil {
					// The channel was closed. We shouldn't be relying on
					// this behavior, but we do the check just in case.
					return
				}
				buf := append([]byte{socketCmdWatch}, boxID...)
				buf = append(buf, pkg...)
				// Send it to our writing goroutine to send it across
				// the socket,
				ss.pkgs <- buf
			}
		}
	}()
}

func (ss socketServer) writeConn() {
	for {
		select {
		case msg := <-ss.messages:
			if err := ss.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
				return
			}
		case pkg := <-ss.pkgs:
			if err := ss.conn.WriteMessage(websocket.BinaryMessage, pkg); err != nil {
				return
			}
		case <-ss.closed:
			return
		}
	}
}

func newSocketServer(conn *websocket.Conn, userID int64) socketServer {
	return socketServer{
		closed:  make(chan bool),
		conn:    conn,
		pkgs:    make(chan []byte, 5),
		pkgSubs: map[string]chan []byte{},
		userID:  userID,
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
