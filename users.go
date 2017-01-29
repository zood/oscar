package main

import (
	crand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

var validUsernamePattern = regexp.MustCompile(`^[a-z0-9]{5,}$`)

const publicUserIDSize = 16

// User ...
type User struct {
	ID                          int64          `json:"-"db:"id"`
	PublicID                    encodableBytes `json:"id,omitempty"`
	Username                    string         `json:"username,omitempty"db:"username"`
	PasswordSalt                encodableBytes `json:"password_salt,omitempty"db:"password_salt"`
	PasswordHashOperationsLimit uint64         `json:"password_hash_operations_limit,omitempty"db:"password_hash_operations_limit"`
	PasswordHashMemoryLimit     uint64         `json:"password_hash_memory_limit,omitempty"db:"password_hash_memory_limit"`
	PublicKey                   encodableBytes `json:"public_key,omitempty"db:"public_key"`
	WrappedSecretKey            encodableBytes `json:"wrapped_secret_key,omitempty"db:"wrapped_secret_key"`
	WrappedSecretKeyNonce       encodableBytes `json:"wrapped_secret_key_nonce,omitempty"db:"wrapped_secret_key_nonce"`
	WrappedSymmetricKey         encodableBytes `json:"wrapped_symmetric_key,omitempty"db:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce    encodableBytes `json:"wrapped_symmetric_key_nonce,omitempty"db:"wrapped_symmetric_key_nonce"`
}

func parseUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	vars := mux.Vars(r)

	pubIDStr := vars["public_id"]
	pubID, err := hex.DecodeString(pubIDStr)
	if err != nil {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), ErrorUserNotFound)
		return 0, false
	}

	var idBytes []byte
	kvdb().View(func(tx *bolt.Tx) error {
		idBytes = tx.Bucket(userIDsBucketName).Get(pubID)
		return nil
	})
	if idBytes == nil {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), ErrorUserNotFound)
		return 0, false
	}

	id := bytesToInt64(idBytes)
	if id < 0 {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), ErrorUserNotFound)
		return 0, false
	}

	return id, true
}

func userIDFromPubID(b []byte) int64 {
	tx, err := kvdb().Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	userIDBytes := tx.Bucket(userIDsBucketName).Get(b)
	return bytesToInt64(userIDBytes)
}

func pubIDFromUserID(id int64) []byte {
	tx, err := kvdb().Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	pubIDBytes := tx.Bucket(publicIDsBucketName).Get(int64ToBytes(id))
	return pubIDBytes
}

// createUserHandler handles POST /users
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	user := User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	pubID, sErr := createUser(user)
	if sErr != nil {
		if sErr.code == ErrorInternal {
			sendInternalErr(w, err)
		} else {
			sendBadReqCode(w, sErr.message, sErr.code)
		}
		return
	}

	sendSuccess(w, struct {
		ID encodableBytes `json:"id"`
	}{ID: pubID})
}

func createUser(user User) ([]byte, *serverError) {
	user.Username = strings.ToLower(strings.TrimSpace(user.Username))
	if user.Username == "" {
		return nil, &serverError{code: ErrorInvalidUsername, message: "Username can not be empty"}
	}
	if !validUsernamePattern.MatchString(user.Username) {
		return nil, &serverError{code: ErrorInvalidUsername, message: "Usernames must be at least 5 characters long and may only contain letters (a-z) or numbers (0-9)."}
	}
	if user.PasswordSalt == nil || len(user.PasswordSalt) == 0 {
		return nil, &serverError{code: ErrorInvalidPasswordSalt, message: "Invalid password salt"}
	}
	if user.PasswordHashOperationsLimit < argon2iOpsLimitInteractive {
		return nil, &serverError{code: ErrorArgon2iOpsLimitTooLow, message: "Password hash ops limit is too low"}
	}
	if user.PasswordHashMemoryLimit < argon2iMemLimitInteractive {
		return nil, &serverError{code: ErrorArgon2iMemLimitTooLow, message: "Password hash mem limit is too low"}
	}
	if user.PublicKey == nil || len(user.PublicKey) != publicKeySize {
		return nil, &serverError{
			code:    ErrorInvalidPublicKey,
			message: fmt.Sprintf("Invalid public key. Expected %d bytes. Found %d.", publicKeySize, len(user.PublicKey)),
		}
	}
	if user.WrappedSecretKey == nil || len(user.WrappedSecretKey) == 0 {
		return nil, &serverError{code: ErrorInvalidWrappedSecretKey, message: "Invalid wrapped secret key"}
	}
	if user.WrappedSecretKeyNonce == nil || len(user.WrappedSecretKeyNonce) == 0 {
		return nil, &serverError{code: ErrorInvalidWrappedSecretKeyNonce, message: "Invalid wrapped secret key nonce"}
	}
	if user.WrappedSymmetricKey == nil || len(user.WrappedSymmetricKey) == 0 {
		return nil, &serverError{code: ErrorInvalidWrappedSymmetricKey, message: "Invalid wrapped symmetric key"}
	}
	if user.WrappedSymmetricKeyNonce == nil || len(user.WrappedSymmetricKeyNonce) == 0 {
		return nil, &serverError{code: ErrorInvalidWrappedSymmetricKeyNonce, message: "Invalid wrapped symmetric key nonce"}
	}

	// check if the username is already in use
	checkUsernameSQL := "SELECT id FROM users WHERE username=?"
	var foundID int
	err := dbx().QueryRow(checkUsernameSQL, user.Username).Scan(&foundID)
	if err == nil {
		return nil, &serverError{code: ErrorUsernameNotAvailable, message: "That username is already in use"}
	}

	insertSQL := `
	INSERT INTO users (	username,
						password_salt,
						password_hash_operations_limit,
						password_hash_memory_limit,
		 				public_key,
						wrapped_secret_key,
						wrapped_secret_key_nonce,
						wrapped_symmetric_key,
						wrapped_symmetric_key_nonce)
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	result, err := dbx().Exec(
		insertSQL,
		user.Username,
		user.PasswordSalt,
		user.PasswordHashOperationsLimit,
		user.PasswordHashMemoryLimit,
		user.PublicKey,
		user.WrappedSecretKey,
		user.WrappedSecretKeyNonce,
		user.WrappedSymmetricKey,
		user.WrappedSymmetricKeyNonce)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	id, err := result.LastInsertId()
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	// create an id for public use
	pubID := make([]byte, publicUserIDSize)
	idExists := true
	tx, err := kvdb().Begin(true)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}
	defer tx.Rollback()
	uidsBucket := tx.Bucket(userIDsBucketName)
	pubIDsBucket := tx.Bucket(publicIDsBucketName)

	for idExists {
		_, err = crand.Read(pubID)
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}

		// check if the id already exists
		val := uidsBucket.Get(pubID)
		if val != nil {
			// someone already has this id, let's try again
			continue
		}
		idExists = false

		err = uidsBucket.Put(pubID, int64ToBytes(id))
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
		err = pubIDsBucket.Put(int64ToBytes(id), pubID)
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
		err = tx.Commit()
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
	}

	return pubID, nil
}

// getUserPublicKeyHandler handles GET /users/{public_id}/public-key
func getUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	selectSQL := `SELECT public_key FROM users WHERE id=?`
	var pubKey []byte
	err := dbx().QueryRow(selectSQL, userID).Scan(&pubKey)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	resp := struct {
		PublicKey encodableBytes `json:"public_key"`
	}{PublicKey: pubKey}

	sendSuccess(w, resp)
}

// searchUsersHandler handles GET /users
func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	username = strings.TrimSpace(username)
	username = strings.ToLower(username)

	user := User{}
	err := dbx().QueryRow("SELECT id, public_key FROM users WHERE username=?", username).Scan(&user.ID, &user.PublicKey)
	switch err {
	case nil:
		user.PublicID = pubIDFromUserID(user.ID)
		user.Username = username
		sendSuccess(w, user)
	case sql.ErrNoRows:
		sendNotFound(w, "user not found", ErrorUserNotFound)
	default:
		sendInternalErr(w, err)
	}
}

func getUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	user := User{}
	err := dbx().QueryRowx("SELECT id, public_key, username FROM users WHERE id=?", userID).StructScan(&user)
	if err != nil {
		// don't need to check for ErrNoRows, because parseUserID ensures the user exists
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, user)
}
