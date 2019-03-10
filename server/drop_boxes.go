package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/internal/pubsub"
	"zood.xyz/oscar/kvstor"
)

const dropBoxIDSize = 16

var dropBoxPubSub = pubsub.New()

const (
	clientCmdNop    byte = 0
	clientCmdWatch       = 1
	clientCmdIgnore      = 2
)

type pkgEvent struct {
	Pkg   encodable.Bytes `json:"package"`
	BoxID encodable.Bytes `json:"box_id"`
}

type subscriptionReader struct {
	sub    chan []byte
	closed chan bool
}

type packageListener struct {
	closed    chan bool
	conn      *websocket.Conn
	kvs       kvstor.Provider
	pkgs      chan []byte
	subs      map[string]subscriptionReader
	waitGroup sync.WaitGroup
}

func (pl *packageListener) ignore(boxID []byte) {
	if len(boxID) != dropBoxIDSize {
		log.Printf("invalid drop box id length (%d)", len(boxID))
		return
	}
	hexID := hex.EncodeToString(boxID)

	// find the channel of this subscription
	sr, ok := pl.subs[hexID]
	if !ok {
		log.Printf("received 'ignore' for non-existent subscription")
		return
	}

	close(sr.closed)
	delete(pl.subs, hexID)
}

func (pl *packageListener) read() {
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

	// unblocks the goroutine that's running stop()
	close(pl.closed)
}

func (pl *packageListener) stop() {
	// wait here until someone tells us to shut down
	<-pl.closed

	// notify every subscription reader to stop
	for _, sr := range pl.subs {
		close(sr.closed)
	}

	// wait until all the subscription readers have completely stopped
	pl.waitGroup.Wait()

	// perform the final clean up
	pl.conn.Close()
	close(pl.pkgs)
}

func (pl *packageListener) start() {
	go pl.read()
	go pl.write()
	go pl.stop()
}

func (pl *packageListener) watch(boxID []byte) {
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

	// create the subscription
	sub := dropBoxPubSub.Sub(hexID)
	sr := subscriptionReader{
		closed: make(chan bool),
		sub:    sub,
	}
	pl.subs[hexID] = sr

	// if there's already a package in the dropbox, send it
	tmp, err := pl.kvs.PickUpPackage(boxID)
	if err != nil {
		logErr(err)
	}
	if len(tmp) > 0 {
		sub <- tmp
	}

	// Wrap up the packages we receive from the subscription, and send them on to
	// the packages channel for writing to the network socket
	pl.waitGroup.Add(1)
	go func(topic string) {
		defer pl.waitGroup.Done()
		defer dropBoxPubSub.Unsub(sub, topic)
		for {
			select {
			case <-pl.closed:
				return
			case pkg := <-sub:
				if pkg == nil {
					return
				}
				bytes := append([]byte{1}, boxID...)
				bytes = append(bytes, pkg...)
				pl.pkgs <- bytes
			}
		}
	}(hexID)
}

func (pl *packageListener) write() {
	for msg := range pl.pkgs {
		err := pl.conn.WriteMessage(websocket.BinaryMessage, msg)
		if err != nil {
			break
		}
	}
}

func newPackageListener(conn *websocket.Conn, kvs kvstor.Provider) *packageListener {
	return &packageListener{
		closed: make(chan bool),
		conn:   conn,
		kvs:    kvs,
		pkgs:   make(chan []byte),
		subs:   make(map[string]subscriptionReader),
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
	boxID, _, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	w.WriteHeader(http.StatusOK)
	kvs := keyValueStorage(r.Context())
	pkg, err := kvs.PickUpPackage(boxID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	w.Write(pkg)
}

// sendMultiplePackagesHandler handles POST /drop-boxes/send
func sendMultiplePackagesHandler(w http.ResponseWriter, r *http.Request) {
	rdr, err := r.MultipartReader()
	if err != nil {
		sendBadReq(w, "unable to read multipart request: "+err.Error())
		return
	}

	var boxes string

	// build the map of boxes => packages
	pkgs := make(map[string][]byte)
	for {
		p, err := rdr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			sendBadReq(w, fmt.Sprintf("error reading part: %s", err.Error()))
			return
		}

		data, err := ioutil.ReadAll(p)
		if err != nil {
			sendBadReq(w, fmt.Sprintf("error reading part data: %s", err.Error()))
			return
		}

		hexBoxID := p.FormName()
		boxID, err := hex.DecodeString(hexBoxID)
		if err != nil {
			sendBadReq(w, "invalid box id: "+err.Error())
			return
		}
		if len(boxID) != dropBoxIDSize {
			sendBadReq(w, "invalid box id size")
			return
		}

		pkgs[hexBoxID] = data

		if shouldLogInfo() {
			boxes += hexBoxID + ", "
		}
	}
	if shouldLogInfo() {
		userID := userIDFromContext(r.Context())
		db := database(r.Context())
		log.Printf("drop_multiple_packages: %s => %s", db.Username(userID), boxes)
	}
	kvs := keyValueStorage(r.Context())
	for hexBoxID, pkg := range pkgs {
		boxID, _ := hex.DecodeString(hexBoxID)
		err := kvs.DropPackage(pkg, boxID)
		if err != nil {
			sendInternalErr(w, err)
			return
		}
	}

	sendSuccess(w, nil)

	go func() {
		for hexBoxID, pkg := range pkgs {
			dropBoxPubSub.Pub(pkg, hexBoxID)
		}
	}()
}

// dropPackageHandler handles PUT /drop-boxes/{box_id}
func dropPackageHandler(w http.ResponseWriter, r *http.Request) {
	boxID, hexBoxID, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	if shouldLogInfo() {
		userID := userIDFromContext(r.Context())
		db := database(r.Context())
		log.Printf("%s dropping pkg to %s", db.Username(userID), hexBoxID)
	}

	if shouldLogDebug() {
		log.Printf("\tdropPkg: about to read request body")
	}
	pkg, err := ioutil.ReadAll(r.Body)
	if shouldLogDebug() {
		log.Printf("\tdropPkg: read request error? %v", err)
	}
	if err != nil {
		sendBadReq(w, "unable to read PUT body: "+err.Error())
		return
	}
	if shouldLogDebug() {
		log.Printf("\tdropPkg: about to update the bucket")
	}
	kvs := keyValueStorage(r.Context())
	err = kvs.DropPackage(pkg, boxID)
	if shouldLogDebug() {
		log.Printf("\tdropPkg: bucket update error? %v", err)
	}
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	if shouldLogDebug() {
		log.Printf("\tdropPkg: sending success")
	}
	sendSuccess(w, nil)

	if shouldLogDebug() {
		log.Printf("\tdropPkg: about to publish package")
	}
	dropBoxPubSub.Pub(pkg, hexBoxID)
	if shouldLogDebug() {
		log.Printf("\tdropPkg: done publishing")
	}
}

func createPackageWatcherHandler(w http.ResponseWriter, r *http.Request) {
	if shouldLogInfo() {
		log.Printf("create_package_watcher")
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

	kvs := keyValueStorage(r.Context())
	pl := newPackageListener(conn, kvs)
	pl.start()
}
