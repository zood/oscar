package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

const userDBsBucketName = "db_backups"

func retrieveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogInfo() {
		log.Printf("download_backup: %s", rs.Username(userID))
	}

	bkt, err := fs.Bucket(userDBsBucketName)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	name := strconv.FormatInt(userID, 10) + ".db"
	exists, err := bkt.ObjectExists(name)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if !exists {
		sendNotFound(w, "no backup found", errorBackupNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	err = bkt.ReadObject(name, w)
	if err != nil {
		// we don't send anything else, because the stream is probably already corrupted
		// by the ReadObject call
		logErr(err)
	}
}

func saveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogInfo() {
		log.Printf("backup: %s", rs.Username(userID))
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendBadReq(w, "Unable to read PUT body: "+err.Error())
		return
	}

	name := strconv.FormatInt(userID, 10) + ".db"
	bkt, err := fs.Bucket(name)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	rdr := bytes.NewReader(buf)
	err = bkt.WriteObject(name, rdr)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
