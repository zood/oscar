package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"zood.dev/oscar/internal/pubsub"
	"zood.dev/oscar/kvstor"
)

const dropBoxIDSize = 16

var dropBoxPubSub = pubsub.New()

const (
	clientCmdNop    byte = 0
	clientCmdWatch  byte = 1
	clientCmdIgnore byte = 2
)

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
		log.Debug().Int("length", len(boxID)).Msg("invalid drop box id length")
		return
	}
	hexID := hex.EncodeToString(boxID)

	// find the channel of this subscription
	sr, ok := pl.subs[hexID]
	if !ok {
		log.Debug().Msg("received 'ignore' for non-existent subscription")
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
			break
		}
		if len(buf) == 0 {
			continue
		}
		switch buf[0] {
		case clientCmdNop:
		case clientCmdWatch:
			pl.watch(buf[1:])
		case clientCmdIgnore:
			pl.ignore(buf[1:])
		default:
			log.Info().Str("command", string(buf[0])).Msg("unknown socket command")
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
		return
	}
	hexID := hex.EncodeToString(boxID)

	// if there's already a sub for this id, skip
	if _, ok := pl.subs[hexID]; ok {
		log.Debug().Msg("skipping duplicate sub request")
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
		log.Err(err).Msg("kvs.PickUpPackage")
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
		sendBadReq(w, "invalid drop box id")
		return nil, "", false
	}

	if len(boxID) != dropBoxIDSize {
		sendBadReq(w, "invalid drop box id")
		return nil, "", false
	}

	return boxID, boxIDStr, true
}

// pickUpPackage handles GET /drop-boxes/{box_id}
func (api httpAPI) pickUpPackage(w http.ResponseWriter, r *http.Request) {
	boxID, _, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	pkg, err := api.kvs.PickUpPackage(boxID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(pkg)
}

// sendMultiplePackagesHandler handles POST /drop-boxes/send
func (api httpAPI) sendMultiplePackages(w http.ResponseWriter, r *http.Request) {
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

		data, err := io.ReadAll(p)
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

		if shouldLogDebug() {
			boxes += hexBoxID + ", "
		}
	}
	if shouldLogDebug() {
		userID := userIDFromContext(r.Context())
		log.Debug().Str("username", api.db.Username(userID)).Str("boxes", boxes).Msg("drop_multiple_packages")
	}
	for hexBoxID, pkg := range pkgs {
		boxID, _ := hex.DecodeString(hexBoxID)
		err := api.kvs.DropPackage(pkg, boxID)
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
func (api httpAPI) dropPackage(w http.ResponseWriter, r *http.Request) {
	boxID, hexBoxID, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	log.Debug().Msg("dropPkg: about to read request body")

	pkg, err := io.ReadAll(r.Body)
	if err != nil {
		log.Debug().Err(err).Msg("dropPkg: read request")
		sendBadReq(w, "unable to read PUT body: "+err.Error())
		return
	}

	log.Debug().Msg("dropPkg: about to update the bucket")
	err = api.kvs.DropPackage(pkg, boxID)
	if err != nil {
		log.Debug().Err(err).Msg("dropPkg: bucket update")
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)

	log.Debug().Msg("dropPkg: about to publish package")
	dropBoxPubSub.Pub(pkg, hexBoxID)
	log.Debug().Msg("dropPkg: done publishing")
}

func (api httpAPI) createPackageWatcher(w http.ResponseWriter, r *http.Request) {
	log.Debug().Msg("create_package_watcher")
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

	pl := newPackageListener(conn, api.kvs)
	pl.start()
}
