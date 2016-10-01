package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

func parseDropBoxID(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	vars := mux.Vars(r)

	boxIDStr := vars["box_id"]
	boxID, err := hex.DecodeString(boxIDStr)
	if err != nil {
		sendBadReq(w, fmt.Sprintf("invalid drop box id"))
		return nil, false
	}

	if len(boxID) != 512 {
		sendBadReq(w, fmt.Sprintf("invalid drop box id"))
		return nil, false
	}

	return boxID, true
}

// getDropBoxPackageHandler handles GET /drop-boxes/{box_id}
func getDropBoxPackageHandler(w http.ResponseWriter, r *http.Request) {
	ok, _ := verifySession(w, r)
	if !ok {
		return
	}

	boxID, ok := parseDropBoxID(w, r)
	if !ok {
		return
	}

	var pkg []byte
	kvdb().View(func(tx *bolt.Tx) error {
		pkg = tx.Bucket(dropboxesBucketName).Get(boxID)
		return nil
	})

	w.WriteHeader(http.StatusOK)
	w.Write(pkg)
	// resp := struct {
	// 	Package encodableBytes `json:"package"`
	// }{Package: pkg}
	//
	// sendSuccess(w, resp)
}

// dropPackageHandler handles POST /drop-boxes/{box_id}
func dropPackageHandler(w http.ResponseWriter, r *http.Request) {
	ok, _ := verifySession(w, r)
	if !ok {
		return
	}

	boxID, ok := parseDropBoxID(w, r)
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
}
