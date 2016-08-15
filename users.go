package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

// User ...
type User struct {
	ID                          int
	Username                    string
	PasswordSalt                []byte
	PasswordHashOperationsLimit uint64
	PasswordHashMemoryLimit     uint64
	PublicKey                   []byte
	WrappedSecretKey            []byte
	WrappedSecretKeyNonce       []byte
	WrappedSymmetricKey         []byte
	WrappedSymmetricKeyNonce    []byte
}

func parseUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	vars := mux.Vars(r)

	pubIDStr := vars["public_id"]
	pubID, err := hex.DecodeString(pubIDStr)
	if err != nil {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr))
		return 0, false
	}

	var idBytes []byte
	kvdb().View(func(tx *bolt.Tx) error {
		idBytes = tx.Bucket(userIDsBucketName).Get(pubID)
		return nil
	})
	if idBytes == nil {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr))
		return 0, false
	}

	id := bytesToInt64(idBytes)
	if id < 0 {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr))
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

// CreateUserHandler handles POST /users
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Username                    string `json:"username"`
		PasswordSalt                string `json:"password_salt"`
		PasswordHashOperationsLimit uint64 `json:"password_hash_operations_limit"`
		PasswordHashMemoryLimit     uint64 `json:"password_hash_memory_limit"`
		PublicKey                   string `json:"public_key"`
		WrappedSecretKey            string `json:"wrapped_secret_key"`
		WrappedSecretKeyNonce       string `json:"wrapped_secret_key_nonce"`
		WrappedSymmetricKey         string `json:"wrapped_symmetric_key"`
		WrappedSymmetricKeyNonce    string `json:"wrapped_symmetric_key_nonce"`
	}{}

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&body)
	if err != nil {
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	user := User{Username: body.Username}
	user.PasswordSalt, err = hex.DecodeString(body.PasswordSalt)
	if err != nil {
		sendBadReq(w, "unable to decode 'password' salt' field from base64: "+err.Error())
		return
	}
	user.PasswordHashOperationsLimit = body.PasswordHashOperationsLimit
	user.PasswordHashMemoryLimit = body.PasswordHashMemoryLimit

	user.PublicKey, err = hex.DecodeString(body.PublicKey)
	if err != nil {
		sendBadReq(w, "unable to decode 'public_key' field from base64: "+err.Error())
		return
	}
	user.WrappedSecretKey, err = hex.DecodeString(body.WrappedSecretKey)
	if err != nil {
		sendBadReq(w, "unable to decode 'wrapped_secret_key' field from base64: "+err.Error())
		return
	}
	user.WrappedSecretKeyNonce, err = hex.DecodeString(body.WrappedSecretKeyNonce)
	if err != nil {
		sendBadReq(w, "unable to decode 'wrapped_secret_key_nonce' field from base64: "+err.Error())
		return
	}
	user.WrappedSymmetricKey, err = hex.DecodeString(body.WrappedSymmetricKey)
	if err != nil {
		sendBadReq(w, "unable to decode 'wrapped_symmetric_key' field from base64: "+err.Error())
		return
	}
	user.WrappedSymmetricKeyNonce, err = hex.DecodeString(body.WrappedSymmetricKeyNonce)
	if err != nil {
		sendBadReq(w, "unable to decode 'wrapped_symmetric_key_nonce' field from base64: "+err.Error())
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
	userID := userIDFromPubID(pubID)

	token, err := newAccessToken(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"id":           hex.EncodeToString(pubID),
		"access_token": token,
	})
}

func createUser(user User) ([]byte, *serverError) {
	if user.Username == "" {
		return nil, &serverError{code: ErrorInvalidUsername, message: "Username can not be empty"}
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
		return nil, &serverError{code: ErrorInvalidPublicKey, message: "Invalid public key"}
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
	err := db().QueryRow(checkUsernameSQL, user.Username).Scan(&foundID)
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
	result, err := db().Exec(insertSQL, user.Username, user.PasswordSalt, user.PasswordHashOperationsLimit, user.PasswordHashMemoryLimit, user.PublicKey, user.WrappedSecretKey, user.WrappedSecretKeyNonce, user.WrappedSymmetricKey, user.WrappedSymmetricKeyNonce)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	id, err := result.LastInsertId()
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	// create a 256-bit id for public use
	pubID := make([]byte, 32)
	idExists := true
	tx, err := kvdb().Begin(true)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}
	defer tx.Rollback()
	bucket := tx.Bucket(userIDsBucketName)

	for idExists {
		_, err = crand.Read(pubID)
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}

		// check if the id already exists
		val := bucket.Get(pubID)
		if val != nil {
			// someone already has this id, let's try again
			continue
		}
		idExists = false

		err = bucket.Put(pubID, int64ToBytes(id))
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

// SearchUsersHandler handles GET /users
func SearchUsersHandler(w http.ResponseWriter, r *http.Request) {
	// username := r.URL.Query().Get("username")
	// if username !=
}
