package main

import (
	"database/sql"
	"net/http"
	"strings"
	"time"
)

func newAccessToken(userID int64) (string, error) {
	token := randAlphaNum(32)

	const insertSQL = `
    INSERT INTO sessions (user_id, access_token, creation_date) VALUES (?, ?, ?)`
	_, err := db().Exec(insertSQL, userID, token, time.Now().Unix())
	if err != nil {
		logErr(err)
		return "", err
	}

	return token, nil
}

func verifySession(w http.ResponseWriter, r *http.Request) (authenticated bool, userID int64) {
	args := r.URL.Query()
	accessToken := args.Get("access_token")
	token := strings.ToLower(strings.TrimSpace(accessToken))
	if token == "" {
		authenticated = false
		sendBadReqCode(w, "invalid access token", ErrorInvalidAccessToken)
		return
	}

	selectSQL := `SELECT user_id FROM sessions WHERE access_token=?`
	err := db().QueryRow(selectSQL, accessToken).Scan(&userID)
	if err == nil {
		authenticated = true
		return
	}

	// check if this was a simple 'not found' or a more serious error
	if err != sql.ErrNoRows {
		logErr(err)
		sendInternalErr(w, err)
	} else {
		sendBadReqCode(w, "invalid access token", ErrorInvalidAccessToken)
	}

	return false, 0
}
