package main

import (
	"bytes"
	crand "crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type sessionChallenge struct {
	ID           int64  `db:"id"`
	UserID       int64  `db:"user_id"`
	CreationDate int64  `db:"creation_date"`
	Challenge    []byte `db:"challenge"`
	SecretKey    []byte `db:"secret_key"`
	PublicKey    []byte `db:"public_key"`
}

type loginResponse struct {
	ID                       encodableBytes `json:"id"`
	AccessToken              string         `json:"access_token"`
	WrappedSymmetricKey      encodableBytes `json:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce encodableBytes `json:"wrapped_symmetric_key_nonce"`
}

func newAccessToken(userID int64) (string, error) {
	token := randBase62(32)

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
	token := r.Header.Get("X-Oscar-Access-Token")
	if token == "" {
		authenticated = false
		sendBadReqCode(w, "invalid access token", ErrorInvalidAccessToken)
		return
	}

	selectSQL := `SELECT user_id FROM sessions WHERE access_token=?`
	err := db().QueryRow(selectSQL, token).Scan(&userID)
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

func createAuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	username = strings.ToLower(username)

	// find the user
	selectSQL := `
	SELECT id, public_key, wrapped_secret_key, wrapped_secret_key_nonce, password_salt, password_hash_operations_limit, password_hash_memory_limit FROM users WHERE username=?`
	user := User{}
	err := db().Get(&user, selectSQL, username)
	if err != nil {
		if err == sql.ErrNoRows {
			sendErr(w, "user not found", http.StatusNotFound, ErrorUserNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	challenge := make([]byte, 255)
	crand.Read(challenge)
	kp, err := generateKeyPair()
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	// delete any existing challenge for this user
	_, err = db().Exec("DELETE FROM session_challenges WHERE user_id=?", user.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	insertSQL := `
	INSERT INTO session_challenges (user_id, creation_date, challenge, secret_key, public_key) VALUES (?, ?, ?, ?, ?)`
	_, err = db().Exec(insertSQL, user.ID, time.Now().Unix(), challenge, kp.secret, kp.public)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	resp := struct {
		User      User           `json:"user"`
		Challenge encodableBytes `json:"challenge"`
		PublicKey encodableBytes `json:"public_key"`
	}{User: user, Challenge: challenge, PublicKey: kp.public}

	sendSuccess(w, resp)
}

func authChallengeResponseHandler(w http.ResponseWriter, r *http.Request) {
	challengeResponse := struct {
		CipherText encodableBytes `json:"cipher_text"`
		Nonce      encodableBytes `json:"nonce"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&challengeResponse)
	if err != nil {
		sendBadReq(w, "unable to parse POST body: "+err.Error())
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]
	username = strings.ToLower(username)

	// we'll retrieve the symmetric key data in case the login in successful
	const userSQL = `
	SELECT id, public_key, wrapped_symmetric_key, wrapped_symmetric_key_nonce FROM users WHERE username=?`
	var userID int64
	var userPubKey []byte
	var wrappedSymKey []byte
	var wrappedSymKeyNonce []byte
	err = db().QueryRow(userSQL, username).Scan(&userID, &userPubKey, &wrappedSymKey, &wrappedSymKeyNonce)
	if err != nil {
		if err == sql.ErrNoRows {
			sendErr(w, "unknown user", http.StatusNotFound, ErrorUserNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	// find the challenge for this user
	const challengeSQL = `
	SELECT id, creation_date, challenge, secret_key, public_key FROM session_challenges WHERE user_id=?`
	challenge := sessionChallenge{}
	err = db().QueryRowx(challengeSQL, userID).StructScan(&challenge)
	if err != nil {
		if err == sql.ErrNoRows {
			sendErr(w, "challenge not found", http.StatusNotFound, ErrorChallengeNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	// if the challenge was created most than 2 minutes ago, then consider it expired
	if (time.Now().Unix() - challenge.CreationDate) > 120 {
		sendBadReqCode(w, "challenge expired", ErrorChallengeExpired)
		go deleteChallenge(challenge.ID)
		return
	}

	origMsg, ok := publicKeyDecrypt(challengeResponse.CipherText, challengeResponse.Nonce, userPubKey, challenge.SecretKey)
	if !ok {
		sendErr(w, "login failed", http.StatusUnauthorized, ErrorLoginFailed)
		return
	}

	// compare the decrypted message with the challenge we sent the user
	if !bytes.Equal(origMsg, challenge.Challenge) {
		// this is not what we wanted them to encrypt
		sendErr(w, "login failed", http.StatusUnauthorized, ErrorLoginFailed)
		return
	}

	// successful challenge. generate a token for them
	pubID := pubIDFromUserID(userID)
	token, err := newAccessToken(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, loginResponse{
		ID:                       pubID,
		AccessToken:              token,
		WrappedSymmetricKey:      wrappedSymKey,
		WrappedSymmetricKeyNonce: wrappedSymKeyNonce})

	go deleteChallenge(challenge.ID)
}

func deleteChallenge(challengeID int64) {
	_, err := db().Exec("DELETE FROM session_challenges WHERE id=?", challengeID)
	if err != nil {
		logErr(err)
	}
}
