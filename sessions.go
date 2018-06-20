package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
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
}

type encryptedData struct {
	CipherText encodableBytes `json:"cipher_text"`
	Nonce      encodableBytes `json:"nonce"`
}

type sessionToken struct {
	Name                  string         `json:"n"`
	CreationDate          int64          `json:"cd"`
	EncryptedCreationDate encodableBytes `json:"ecd"`
}

type loginResponse struct {
	ID                       encodableBytes `json:"id"`
	AccessToken              string         `json:"access_token"`
	WrappedSymmetricKey      encodableBytes `json:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce encodableBytes `json:"wrapped_symmetric_key_nonce"`
}

func userIDFromContext(ctx context.Context) int64 {
	return ctx.Value(contextUserIDKey).(int64)
}

func sendInvalidAccessToken(w http.ResponseWriter) {
	sendBadReqCode(w, "invalid access token", errorInvalidAccessToken)
}

func sessionHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Oscar-Access-Token")
		if token == "" {
			sendInvalidAccessToken(w)
			return
		}

		// base64 => decrypt token => get user's public key => decrypt inner token => make sure creation dates match
		encryptedTokenBytes, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			sendInvalidAccessToken(w)
			return
		}
		if len(encryptedTokenBytes) < secretBoxNonceSize+10 {
			sendInvalidAccessToken(w)
			return
		}
		tokenNonce := encryptedTokenBytes[:secretBoxNonceSize]
		tokenCipherText := encryptedTokenBytes[secretBoxNonceSize:]
		decryptedToken, ok := symmetricKeyDecrypt(tokenCipherText, tokenNonce, oscarSymKey)
		if !ok {
			sendInvalidAccessToken(w)
			return
		}

		st := sessionToken{}
		err = json.Unmarshal(decryptedToken, &st)
		if err != nil {
			sendInvalidAccessToken(w)
			return
		}

		// sanity check on decoded JSON
		if st.CreationDate == 0 || len(st.EncryptedCreationDate) < secretBoxNonceSize+10 || st.Name == "" {
			sendInvalidAccessToken(w)
			return
		}

		// get the user's public key
		selectUserInfoSQL := `SELECT id, public_key FROM users WHERE username=?`
		var userID int64
		pubKey := make([]byte, 0)
		err = dbx().QueryRow(selectUserInfoSQL, st.Name).Scan(&userID, &pubKey)
		if err != nil {
			if err == sql.ErrNoRows {
				sendInvalidAccessToken(w)
			} else {
				sendInternalErr(w, err)
			}
			return
		}

		if len(pubKey) == 0 {
			log.Printf("public key is empty/nil")
			sendInvalidAccessToken(w)
			return
		}

		cdNonce := st.EncryptedCreationDate[:secretBoxNonceSize]
		cdCipherText := st.EncryptedCreationDate[secretBoxNonceSize:]
		dcdCreationDateBytes, ok := publicKeyDecrypt(cdCipherText, cdNonce, pubKey, oscarKeyPair.secret)
		if !ok {
			sendInvalidAccessToken(w)
			return
		}
		dcdCreationDate, err := bytesToInt64Err(dcdCreationDateBytes)
		if err != nil {
			sendInvalidAccessToken(w)
			return
		}
		if dcdCreationDate != st.CreationDate {
			log.Printf("server creation date differed from user encrypted creation date")
			sendInvalidAccessToken(w)
			return
		}

		// everything checks out!
		ctx := context.WithValue(r.Context(), contextUserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func createAuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	username = strings.ToLower(username)

	// find the user
	selectSQL := `
	SELECT id, public_key, wrapped_secret_key, wrapped_secret_key_nonce, password_salt, password_hash_algorithm, password_hash_operations_limit, password_hash_memory_limit FROM users WHERE username=?`
	user := User{}
	err := dbx().Get(&user, selectSQL, username)
	if err != nil {
		if err == sql.ErrNoRows {
			sendNotFound(w, "user not found", errorUserNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	challenge := make([]byte, 255)
	crand.Read(challenge)

	// delete any existing challenge for this user
	_, err = dbx().Exec("DELETE FROM session_challenges WHERE user_id=?", user.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	creationDate := time.Now().Unix()

	insertSQL := `
	INSERT INTO session_challenges (user_id, creation_date, challenge) VALUES (?, ?, ?)`
	_, err = dbx().Exec(insertSQL, user.ID, creationDate, challenge)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	resp := struct {
		User         User           `json:"user"`
		Challenge    encodableBytes `json:"challenge"`
		CreationDate encodableBytes `json:"creation_date"`
	}{User: user, Challenge: challenge, CreationDate: int64ToBytes(creationDate)}

	sendSuccess(w, resp)
}

func finishAuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
	authResponse := struct {
		Challenge    encryptedData `json:"challenge"`
		CreationDate encryptedData `json:"creation_date"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&authResponse)
	if err != nil {
		sendBadReq(w, "unable to parse POST body: "+err.Error())
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]
	username = strings.ToLower(username)

	// we also retrieve the symmetric key data in case the login is successful
	const userSQL = `
	SELECT id, public_key, wrapped_symmetric_key, wrapped_symmetric_key_nonce FROM users WHERE username=?`
	var userID int64
	var userPubKey []byte
	var wrappedSymKey []byte
	var wrappedSymKeyNonce []byte
	err = dbx().QueryRow(userSQL, username).Scan(&userID, &userPubKey, &wrappedSymKey, &wrappedSymKeyNonce)
	if err != nil {
		if err == sql.ErrNoRows {
			sendNotFound(w, "unknown user", errorUserNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	// find the challenge for this user
	const challengeSQL = `
	SELECT id, creation_date, challenge FROM session_challenges WHERE user_id=?`
	challenge := sessionChallenge{}
	err = dbx().QueryRowx(challengeSQL, userID).StructScan(&challenge)
	if err != nil {
		if err == sql.ErrNoRows {
			sendNotFound(w, "challenge not found", errorChallengeNotFound)
		} else {
			sendInternalErr(w, err)
		}
		return
	}

	// if the challenge was created most than 2 minutes ago, then consider it expired
	if (time.Now().Unix() - challenge.CreationDate) > 120 {
		sendBadReqCode(w, "challenge expired", errorChallengeExpired)
		go deleteChallenge(challenge.ID)
		return
	}

	decryptedChallenge, ok := publicKeyDecrypt(authResponse.Challenge.CipherText, authResponse.Challenge.Nonce, userPubKey, oscarKeyPair.secret)
	if !ok {
		sendErr(w, "login failed", http.StatusUnauthorized, errorLoginFailed)
		return
	}
	if decryptedChallenge == nil || len(decryptedChallenge) == 0 {
		sendErr(w, "login failed", http.StatusUnauthorized, errorLoginFailed)
		return
	}
	// compare the decrypted message with the challenge we sent the user
	if !bytes.Equal(decryptedChallenge, challenge.Challenge) {
		// this is not what we wanted them to encrypt
		sendErr(w, "login failed", http.StatusUnauthorized, errorLoginFailed)
		return
	}

	decryptedCreationDate, ok := publicKeyDecrypt(authResponse.CreationDate.CipherText, authResponse.CreationDate.Nonce, userPubKey, oscarKeyPair.secret)
	if !ok {
		sendErr(w, "login failed", http.StatusUnauthorized, errorLoginFailed)
		return
	}
	// compare the decrypted creation date with the original
	if !bytes.Equal(decryptedCreationDate, int64ToBytes(challenge.CreationDate)) {
		sendErr(w, "login failed", http.StatusUnauthorized, errorLoginFailed)
		return
	}

	// successful challenge; create a token for the user
	// raw token -> json -> encrypt with server sym key -> base64 -> give to user
	token := sessionToken{
		Name:                  username,
		CreationDate:          challenge.CreationDate,
		EncryptedCreationDate: append(authResponse.CreationDate.Nonce, authResponse.CreationDate.CipherText...),
	}

	tokenBytes, err := json.Marshal(token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	tokenCT, tokenNonce, err := symmetricKeyEncrypt(tokenBytes, oscarSymKey)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	accessToken := append(tokenNonce, tokenCT...)
	accessTokenB64 := base64.StdEncoding.EncodeToString(accessToken)

	pubID := pubIDFromUserID(userID)

	sendSuccess(w, loginResponse{
		ID:                       pubID,
		AccessToken:              accessTokenB64,
		WrappedSymmetricKey:      wrappedSymKey,
		WrappedSymmetricKeyNonce: wrappedSymKeyNonce})

	go deleteChallenge(challenge.ID)
}

func deleteChallenge(challengeID int64) {
	_, err := dbx().Exec("DELETE FROM session_challenges WHERE id=?", challengeID)
	if err != nil {
		logErr(err)
	}
}
