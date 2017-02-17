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
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

var validUsernamePattern = regexp.MustCompile(`^[a-z0-9]{5,}$`)

const publicUserIDSize = 16

// User ...
type User struct {
	ID                          int64          `json:"-" db:"id"`
	PublicID                    encodableBytes `json:"id,omitempty"`
	Username                    string         `json:"username,omitempty" db:"username"`
	PasswordSalt                encodableBytes `json:"password_salt,omitempty" db:"password_salt"`
	PasswordHashOperationsLimit uint64         `json:"password_hash_operations_limit,omitempty" db:"password_hash_operations_limit"`
	PasswordHashMemoryLimit     uint64         `json:"password_hash_memory_limit,omitempty" db:"password_hash_memory_limit"`
	PublicKey                   encodableBytes `json:"public_key,omitempty" db:"public_key"`
	WrappedSecretKey            encodableBytes `json:"wrapped_secret_key,omitempty" db:"wrapped_secret_key"`
	WrappedSecretKeyNonce       encodableBytes `json:"wrapped_secret_key_nonce,omitempty" db:"wrapped_secret_key_nonce"`
	WrappedSymmetricKey         encodableBytes `json:"wrapped_symmetric_key,omitempty" db:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce    encodableBytes `json:"wrapped_symmetric_key_nonce,omitempty" db:"wrapped_symmetric_key_nonce"`
	Email                       string         `json:"email" db:"email"`
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
	user.Email = strings.TrimSpace(strings.ToLower(user.Email))
	var emailVerificationToken *string
	if user.Email != "" {
		if len(user.Email) > 254 {
			return nil, &serverError{code: ErrorInvalidEmail, message: "Email address is too long"}
		}
		parts := strings.Split(user.Email, "@")
		if len(parts) != 2 {
			return nil, &serverError{code: ErrorInvalidEmail, message: "Email address doesn't have a user and domain separated by an '@'"}
		}
		if parts[0] == "" {
			return nil, &serverError{code: ErrorInvalidEmail, message: "Invalid user component in email"}
		}
		domainParts := strings.Split(parts[1], ".")
		if len(domainParts) < 2 {
			return nil, &serverError{code: ErrorInvalidEmail, message: "Invalid domain in email address"}
		}
		tld := domainParts[len(domainParts)-1]
		if len(tld) < 2 {
			return nil, &serverError{code: ErrorInvalidEmail, message: "Invalid tld in domain"}
		}

		// everything looks good, so let's generate a verification token
		token := randBase62(16)
		emailVerificationToken = &token
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
	tx, err := dbx().Beginx()
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}
	defer tx.Rollback()
	result, err := tx.Exec(
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

	// if there was an email address, add a record for the token
	if emailVerificationToken != nil {
		insertSQL = `INSERT INTO email_verification_tokens (user_id, token, email, send_date) VALUES (?, ?, ?, ?)`
		_, err = tx.Exec(insertSQL, id, *emailVerificationToken, user.Email, time.Now().Unix())
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
	}
	err = tx.Commit()
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	// create an id for public use
	pubID := make([]byte, publicUserIDSize)
	idExists := true
	kvTx, err := kvdb().Begin(true)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}
	defer kvTx.Rollback()
	uidsBucket := kvTx.Bucket(userIDsBucketName)
	pubIDsBucket := kvTx.Bucket(publicIDsBucketName)

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
		err = kvTx.Commit()
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
	}

	if emailVerificationToken != nil {
		go func() {
			err = sendVerificationEmail(*emailVerificationToken, user.Email)
			if err != nil {
				logErr(err)
			}
		}()
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
