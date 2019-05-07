package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"zood.xyz/oscar/base62"
	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/relstor"
	"zood.xyz/oscar/sodium"
)

type sessionChallenge struct {
	ID           int64  `db:"id"`
	UserID       int64  `db:"user_id"`
	CreationDate int64  `db:"creation_date"`
	Challenge    []byte `db:"challenge"`
}

type encryptedData struct {
	CipherText encodable.Bytes `json:"cipher_text"`
	Nonce      encodable.Bytes `json:"nonce"`
}

type sessionToken struct {
	Name                  string          `json:"n"`
	CreationDate          int64           `json:"cd"`
	EncryptedCreationDate encodable.Bytes `json:"ecd"`
}

type loginResponse struct {
	ID                       encodable.Bytes `json:"id"`
	AccessToken              string          `json:"access_token"`
	WrappedSymmetricKey      encodable.Bytes `json:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce encodable.Bytes `json:"wrapped_symmetric_key_nonce"`
}

const ticketLength = 16

func createAuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]
	username = strings.ToLower(username)

	// find the user
	db := providersCtx(r.Context()).db
	userRec, err := db.User(username)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if userRec == nil {
		sendNotFound(w, "user not found", errorUserNotFound)
		return
	}

	// only a subset of the user should be returned for an authentication challenge
	user := User{
		PublicKey:                   userRec.PublicKey,
		WrappedSecretKey:            userRec.WrappedSecretKey,
		WrappedSecretKeyNonce:       userRec.WrappedSecretKeyNonce,
		PasswordSalt:                userRec.PasswordSalt,
		PasswordHashAlgorithm:       userRec.PasswordHashAlgorithm,
		PasswordHashOperationsLimit: userRec.PasswordHashOperationsLimit,
		PasswordHashMemoryLimit:     userRec.PasswordHashMemoryLimit,
	}

	challenge := make([]byte, 255)
	crand.Read(challenge)

	// delete any existing challenge for this user
	err = db.DeleteSessionChallengeUser(userRec.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	creationDate := time.Now().Unix()

	err = db.InsertSessionChallenge(userRec.ID, creationDate, challenge)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	resp := struct {
		User         User            `json:"user"`
		Challenge    encodable.Bytes `json:"challenge"`
		CreationDate encodable.Bytes `json:"creation_date"`
	}{User: user, Challenge: challenge, CreationDate: int64ToBytes(creationDate)}

	sendSuccess(w, resp)
}

func createTicketHandler(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	ticket := base62.Rand(ticketLength)
	db := providersCtx(r.Context()).db
	err := db.InsertTicket(ticket, userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, struct {
		Ticket string `json:"ticket"`
	}{Ticket: ticket})
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

	providers := providersCtx(r.Context())
	db := providers.db
	user, err := db.User(username)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if user == nil {
		sendNotFound(w, "unknown user", errorUserNotFound)
		return
	}

	// find the challenge for this user
	challenge, err := db.SessionChallenge(user.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if challenge == nil {
		sendNotFound(w, "challenge not found", errorChallengeNotFound)
		return
	}

	// if the challenge was created more than 2 minutes ago, then consider it expired
	if (time.Now().Unix() - challenge.CreationDate) > 120 {
		sendBadReqCode(w, "challenge expired", errorChallengeExpired)
		go db.DeleteSessionChallengeID(challenge.ID)
		return
	}

	decryptedChallenge, ok := sodium.PublicKeyDecrypt(authResponse.Challenge.CipherText, authResponse.Challenge.Nonce, user.PublicKey, providers.keyPair.Secret)
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

	decryptedCreationDate, ok := sodium.PublicKeyDecrypt(authResponse.CreationDate.CipherText, authResponse.CreationDate.Nonce, user.PublicKey, providers.keyPair.Secret)
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

	tokenCT, tokenNonce, err := sodium.SymmetricKeyEncrypt(tokenBytes, providers.symKey)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	accessToken := append(tokenNonce, tokenCT...)
	accessTokenB64 := base64.StdEncoding.EncodeToString(accessToken)

	kvs := providersCtx(r.Context()).kvs
	pubID, err := kvs.PublicIDFromUserID(user.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, loginResponse{
		ID:                       pubID,
		AccessToken:              accessTokenB64,
		WrappedSymmetricKey:      user.WrappedSymmetricKey,
		WrappedSymmetricKeyNonce: user.WrappedSymmetricKeyNonce})

	go db.DeleteSessionChallengeID(challenge.ID)
}

func sendInvalidAccessToken(w http.ResponseWriter) {
	sendErr(w, "invalid/missing access token", http.StatusUnauthorized, errorInvalidAccessToken)
}

func sessionHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Oscar-Access-Token")
		log.Printf("checking token: %s", token)
		providers := providersCtx(r.Context())
		userID, err := verifyAccessToken(providers.db, providers.symKey, providers.keyPair, token)
		if err != nil {
			sendInternalErr(w, err)
			return
		}
		if userID == 0 {
			sendInvalidAccessToken(w)
			return
		}

		// everything checks out!
		ctx := context.WithValue(r.Context(), contextUserIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func userIDFromContext(ctx context.Context) int64 {
	return ctx.Value(contextUserIDKey).(int64)
}

func verifyAccessToken(db relstor.Provider, serverSymKey []byte, serverKeyPair sodium.KeyPair, token string) (int64, error) {
	if token == "" {
		return 0, nil
	}

	// base64 => decrypt token => get user's public key => decrypt inner token => make sure creation dates match
	encryptedTokenBytes, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, nil
	}
	if len(encryptedTokenBytes) < sodium.SymmetricNonceSize+10 {
		return 0, nil
	}
	tokenNonce := encryptedTokenBytes[:sodium.SymmetricNonceSize]
	tokenCipherText := encryptedTokenBytes[sodium.SymmetricNonceSize:]
	decryptedToken, ok := sodium.SymmetricKeyDecrypt(tokenCipherText, tokenNonce, serverSymKey)
	if !ok {
		return 0, nil
	}

	st := sessionToken{}
	err = json.Unmarshal(decryptedToken, &st)
	if err != nil {
		return 0, nil
	}

	// sanity check on decoded JSON
	if st.CreationDate == 0 || len(st.EncryptedCreationDate) < sodium.SymmetricNonceSize+10 || st.Name == "" {
		return 0, nil
	}

	// get the user's public key
	userID, pubKey, err := db.LimitedUserInfo(st.Name)
	if err != nil {
		return 0, err
	}
	if pubKey == nil {
		return 0, nil
	}

	cdNonce := st.EncryptedCreationDate[:sodium.SymmetricNonceSize]
	cdCipherText := st.EncryptedCreationDate[sodium.SymmetricNonceSize:]
	dcdCreationDateBytes, ok := sodium.PublicKeyDecrypt(cdCipherText, cdNonce, pubKey, serverKeyPair.Secret)
	if !ok {
		return 0, nil
	}
	dcdCreationDate, err := bytesToInt64Err(dcdCreationDateBytes)
	if err != nil {
		return 0, nil
	}
	if dcdCreationDate != st.CreationDate {
		log.Printf("server creation date differed from user encrypted creation date")
		return 0, nil
	}

	return userID, nil
}

func verifySessionTicket(db relstor.Provider, ticket string) (int64, error) {
	userID, timestamp, err := db.Ticket(ticket)
	if err != nil {
		return 0, errors.Wrap(err, "failed to query for ticket")
	}

	if userID == 0 {
		return 0, nil
	}

	// We found it, but we have to make sure it's not too old.
	// Also, use this opportunity to delete old tickets
	now := time.Now().Unix()
	defer db.DeleteTickets(now - 60)

	// the ticket can't be older than 60 seconds
	if timestamp < now-60 {
		return 0, nil
	}
	// we're good to go!
	return userID, nil
}
