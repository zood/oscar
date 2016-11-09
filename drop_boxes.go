package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/boltdb/bolt"
	"github.com/cskr/pubsub"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

const dropBoxIDSize = 16

var dropBoxPubSub = pubsub.New(1)

const (
	clientCmdNop    byte = 0
	clientCmdWatch       = 1
	clientCmdIgnore      = 2
)

type pkgEvent struct {
	Pkg   encodableBytes `json:"package"`
	BoxID encodableBytes `json:"box_id"`
}

type packageListener struct {
	conn *websocket.Conn
	pkgs chan []byte
	subs map[string]chan interface{}
}

func (pl packageListener) ignore(boxID []byte) {
	if len(boxID) != dropBoxIDSize {
		log.Printf("invalid drop box id length (%d)", len(boxID))
		return
	}
	hexID := hex.EncodeToString(boxID)

	// find the channel of this subscription
	sub, ok := pl.subs[hexID]
	if !ok {
		log.Printf("received 'ignore' for non-existent subscription")
		return
	}

	dropBoxPubSub.Unsub(sub)
	delete(pl.subs, hexID)
}

func (pl packageListener) read() {
	for {
		msgType, buf, err := pl.conn.ReadMessage()
		if err != nil {
			break
		}
		if msgType != websocket.BinaryMessage {
			log.Printf("received a non-binary message")
			break
		}
		if len(buf) == 0 {
			log.Printf("received an invalid length message from client (%d). ignoring", len(buf))
			continue
		}
		switch buf[0] {
		case clientCmdNop:
		case clientCmdWatch:
			pl.watch(buf[1:])
		case clientCmdIgnore:
			pl.ignore(buf[1:])
		default:
			log.Printf("unknown socket command: %d", buf[0])
		}
	}

	// unsubscribe every channel we have
	for _, ch := range pl.subs {
		dropBoxPubSub.Unsub(ch)
	}

	close(pl.pkgs)
	pl.conn.Close()
}

func (pl packageListener) watch(boxID []byte) {
	if len(boxID) != dropBoxIDSize {
		log.Printf("invalid drop box id length (%d)", len(boxID))
		return
	}
	hexID := hex.EncodeToString(boxID)

	// if there's already a sub for this id, skip
	if _, ok := pl.subs[hexID]; ok {
		log.Printf("Duplicate sub request. Skipping.")
		return
	}

	sub := dropBoxPubSub.Sub(hexID)
	pl.subs[hexID] = sub
	go func() {
		tmp := pickUpPackage(boxID)
		if len(tmp) > 0 {
			sub <- tmp
		}
		for pkg := range sub {
			bytes := append([]byte{1}, boxID...)
			bytes = append(bytes, pkg.([]byte)...)
			pl.pkgs <- bytes
		}
	}()
}

func (pl packageListener) write() {
	for msg := range pl.pkgs {
		err := pl.conn.WriteMessage(websocket.BinaryMessage, msg)
		if err != nil {
			break
		}
	}
}

func (pl packageListener) start() {
	go pl.read()
	go pl.write()
}

func newPackageListener(conn *websocket.Conn) packageListener {
	return packageListener{
		conn: conn,
		pkgs: make(chan []byte),
		subs: make(map[string]chan interface{}),
	}
}

func parseDropBoxID(w http.ResponseWriter, r *http.Request) ([]byte, string, bool) {
	vars := mux.Vars(r)

	boxIDStr := vars["box_id"]
	boxID, err := hex.DecodeString(boxIDStr)
	if err != nil {
		sendBadReq(w, fmt.Sprintf("invalid drop box id"))
		return nil, "", false
	}

	if len(boxID) != dropBoxIDSize {
		sendBadReq(w, fmt.Sprintf("invalid drop box id"))
		return nil, "", false
	}

	return boxID, boxIDStr, true
}

// pickUpPackageHandler handles GET /drop-boxes/{box_id}
func pickUpPackageHandler(w http.ResponseWriter, r *http.Request) {
	ok, _ := verifySession(w, r)
	if !ok {
		return
	}

	boxID, _, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(pickUpPackage(boxID))
}

func pickUpPackage(boxID []byte) []byte {
	var pkg []byte
	kvdb().View(func(tx *bolt.Tx) error {
		pkg = tx.Bucket(dropboxesBucketName).Get(boxID)
		return nil
	})

	return pkg
}

// dropPackageHandler handles POST /drop-boxes/{box_id}
func dropPackageHandler(w http.ResponseWriter, r *http.Request) {
	ok, _ := verifySession(w, r)
	if !ok {
		return
	}

	boxID, hexBoxID, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	pkg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendBadReq(w, "unable to read POST body: "+err.Error())
		return
	}
	err = kvdb().Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dropboxesBucketName)
		err := bucket.Put(boxID, pkg)
		return err
	})
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)

	dropBoxPubSub.Pub(pkg, hexBoxID)
}

func createPackageWatcherHandler(w http.ResponseWriter, r *http.Request) {
	ok, _ := verifySession(w, r)
	if !ok {
		return
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// we don't need to do anything. The upgrader sends 400 on our behalf.
		return
	}

	pl := newPackageListener(conn)
	pl.start()
}
