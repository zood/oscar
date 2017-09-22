package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

var userDBBackupFiles string

func retrieveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogInfo() {
		log.Printf("download_backup: %s", usernameFromID(userID))
	}

	fileLoc := filepath.Join(userDBBackupFiles, strconv.FormatInt(userID, 10)+".db")
	_, err := os.Stat(fileLoc)
	if err != nil {
		if os.IsNotExist(err) {
			sendNotFound(w, "no backup found", errorBackupNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	file, err := os.Open(fileLoc)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	defer file.Close()

	io.Copy(w, file)
}

func saveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogInfo() {
		log.Printf("backup: %s", usernameFromID(userID))
	}

	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		sendBadReq(w, "Unable to PUT body: "+err.Error())
		return
	}

	fileLoc := filepath.Join(userDBBackupFiles, strconv.FormatInt(userID, 10)+".db")
	file, err := os.Create(fileLoc)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	defer file.Close()

	_, err = file.Write(buf)
	if err != nil {
		sendInternalErr(w, err)
		file.Close()
		os.Remove(fileLoc)
		return
	}
	file.Close()

	sendSuccess(w, nil)
}
