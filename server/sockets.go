package main

import (
	"encoding/hex"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
	"zood.dev/oscar/internal/pubsub"
	"zood.dev/oscar/kvstor"
)

const (
	socketClientCmdNop    byte = 0
	socketClientCmdWatch  byte = 1
	socketClientCmdIgnore byte = 2
)

const (
	socketServerCmdPackage          byte = 1
	socketServerCmdPushNotification byte = 2
)

var messagesPubSub = pubsub.NewInt64()

type socketServer struct {
	conn     *websocket.Conn
	closed   chan bool
	kvs      kvstor.Provider
	messages chan []byte
	pkgs     chan []byte
	pkgSubs  map[string]chan []byte
	userID   int64
}

func (ss socketServer) ignoreBox(boxID []byte) {
	hexID := hex.EncodeToString(boxID)
	sub := ss.pkgSubs[hexID]
	if sub == nil {
		// We don't have a subscription for this box. Client error!
		log.Printf("A client tried unsubscribing from a drop box to which they hadn't subscribed")
		return
	}
	dropBoxPubSub.Unsub(sub, hexID)
	delete(ss.pkgSubs, hexID)
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
		case socketClientCmdNop:
		case socketClientCmdWatch:
			ss.watchBox(buf[1:])
		case socketClientCmdIgnore:
			ss.ignoreBox(buf[1:])
		default:
			log.Printf("unknown socket command: %d", buf[0])
		}
	}
}

func (ss socketServer) start() {
	ss.messages = messagesPubSub.Sub(ss.userID)
	go ss.readConn()
	go ss.writeConn()
	go ss.stop()
}

func (ss socketServer) stop() {
	// wait here until someone tells us to shut down
	<-ss.closed

	// stop listening for packages
	for hexBoxID, sub := range ss.pkgSubs {
		dropBoxPubSub.Unsub(sub, hexBoxID)
	}
	// stop listening for messages
	messagesPubSub.Unsub(ss.messages, ss.userID)

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
		log.Printf("A client requested a 'watch' for the same box more than once")
		return
	}

	// create a subscription
	sub := dropBoxPubSub.Sub(hexID)
	ss.pkgSubs[hexID] = sub

	// If there's already a package in the dropbox, send it
	tmp, err := ss.kvs.PickUpPackage(boxID)
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
			case pkg, ok := <-sub:
				if !ok {
					return
				}
				buf := append([]byte{socketServerCmdPackage}, boxID...)
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
			if msg == nil {
				return
			}
			buf := append([]byte{socketServerCmdPushNotification}, msg...)
			if err := ss.conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
				return
			}
		case pkg := <-ss.pkgs:
			if pkg == nil {
				return
			}
			if err := ss.conn.WriteMessage(websocket.BinaryMessage, pkg); err != nil {
				return
			}
		case <-ss.closed:
			return
		}
	}
}

func newSocketServer(conn *websocket.Conn, userID int64, kvs kvstor.Provider) socketServer {
	return socketServer{
		closed:  make(chan bool),
		conn:    conn,
		kvs:     kvs,
		pkgs:    make(chan []byte, 5),
		pkgSubs: map[string]chan []byte{},
		userID:  userID,
	}
}

func createSocketHandler(w http.ResponseWriter, r *http.Request) {
	// check the 'Sec-Websocket-Protocol' header for an access token
	token := r.Header.Get("Sec-Websocket-Protocol")
	providers := providersCtx(r.Context())
	db := providers.db
	userID, err := verifyAccessToken(db, token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if userID == 0 {
		// check if they specified a ticket
		ticket := r.URL.Query().Get("ticket")
		userID, err = verifySessionTicket(db, ticket)
		if err != nil {
			sendInternalErr(w, err)
			return
		}
		// if the user id is still 0, then reject the request
		if userID == 0 {
			sendInvalidAccessToken(w)
			return
		}
	}

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

	kvs := providers.kvs
	ss := newSocketServer(conn, userID, kvs)
	ss.start()
}
