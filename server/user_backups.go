package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strconv"

	"zood.dev/oscar/filestor"
)

// const userDBsBucketName = "db_backups"
const dbBackupsDir = "db_backups"

func retrieveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	providers := providersCtx(r.Context())
	db := providers.db
	if shouldLogInfo() {
		log.Printf("download_backup: %s", db.Username(userID))
	}

	relPath := filepath.Join(dbBackupsDir, strconv.FormatInt(userID, 10)+".db")
	fs := providers.fs
	err := fs.ReadFile(relPath, w)
	if err != nil {
		if err == filestor.ErrFileNotExist {
			sendNotFound(w, "no backup found", errorBackupNotFound)
			return
		}
		// this might not be the best response, but let's try it out
		sendInternalErr(w, err)
		return
	}
}

func saveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	providers := providersCtx(r.Context())
	db := providers.db
	if shouldLogInfo() {
		log.Printf("backup: %s", db.Username(userID))
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendBadReq(w, "Unable to read PUT body: "+err.Error())
		return
	}

	relPath := filepath.Join(dbBackupsDir, strconv.FormatInt(userID, 10)+".db")
	rdr := bytes.NewReader(buf)
	fs := providers.fs
	err = fs.WriteFile(relPath, rdr)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}
