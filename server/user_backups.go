package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/rs/zerolog/log"
	"zood.dev/oscar/filestor"
)

func userBackupFilePath(userID int64) string {
	const dbBackupsDir = "db_backups"
	return path.Join(dbBackupsDir, strconv.FormatInt(userID, 10)+".db")
}

func (api httpAPI) retrieveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogDebug() {
		log.Debug().Str("username", api.db.Username(userID)).Msg("download_backup")
	}

	err := api.fs.ReadFile(userBackupFilePath(userID), w)
	if err != nil {
		if errors.Is(err, filestor.ErrFileNotExist) {
			sendNotFound(w, "no backup found", errorBackupNotFound)
			return
		}
		// this might not be the best response, but let's try it out
		sendInternalErr(w, err)
		return
	}
}

func (api httpAPI) saveBackupHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	if shouldLogDebug() {
		log.Debug().Str("username", api.db.Username(userID)).Msg("backup")
	}

	buf, err := io.ReadAll(r.Body)
	if err != nil {
		sendBadReq(w, "Unable to read PUT body: "+err.Error())
		return
	}

	rdr := bytes.NewReader(buf)
	err = api.fs.WriteFile(userBackupFilePath(userID), rdr)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, nil)
}
