package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"zood.dev/oscar/base62"
	"zood.dev/oscar/encodable"
	"zood.dev/oscar/kvstor"
	"zood.dev/oscar/model"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

var validUsernamePattern = regexp.MustCompile(`^[a-z0-9]{5,}$`)

const publicUserIDSize = 16

// User ...
type User struct {
	ID                          int64           `json:"-" db:"id"`
	PublicID                    encodable.Bytes `json:"id,omitempty"`
	Username                    string          `json:"username,omitempty" db:"username"`
	PasswordSalt                encodable.Bytes `json:"password_salt,omitempty" db:"password_salt"`
	PasswordHashAlgorithm       string          `json:"password_hash_algorithm" db:"password_hash_algorithm"`
	PasswordHashOperationsLimit uint            `json:"password_hash_operations_limit,omitempty" db:"password_hash_operations_limit"`
	PasswordHashMemoryLimit     uint64          `json:"password_hash_memory_limit,omitempty" db:"password_hash_memory_limit"`
	PublicKey                   encodable.Bytes `json:"public_key,omitempty" db:"public_key"`
	WrappedSecretKey            encodable.Bytes `json:"wrapped_secret_key,omitempty" db:"wrapped_secret_key"`
	WrappedSecretKeyNonce       encodable.Bytes `json:"wrapped_secret_key_nonce,omitempty" db:"wrapped_secret_key_nonce"`
	WrappedSymmetricKey         encodable.Bytes `json:"wrapped_symmetric_key,omitempty" db:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce    encodable.Bytes `json:"wrapped_symmetric_key_nonce,omitempty" db:"wrapped_symmetric_key_nonce"`
	Email                       string          `json:"email" db:"email"`
}

func parseUserID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	vars := mux.Vars(r)

	pubIDStr := vars["public_id"]
	pubID, err := hex.DecodeString(pubIDStr)
	if err != nil {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), errorUserNotFound)
		return 0, false
	}

	kvs := providersCtx(r.Context()).kvs
	id, err := kvs.UserIDFromPublicID(pubID)
	if err != nil {
		sendInternalErr(w, err)
		return 0, false
	}
	if id < 1 {
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), errorUserNotFound)
		return 0, false
	}

	return id, true
}

// createUserHandler handles POST /users
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	user := User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	ctx := r.Context()
	providers := providersCtx(ctx)
	pubID, sErr := createUser(providers.db, providers.kvs, providers.emailer, user)
	if sErr != nil {
		if sErr.code == errorInternal {
			sendInternalErr(w, err)
		} else {
			sendBadReqCode(w, sErr.message, sErr.code)
		}
		return
	}

	sendSuccess(w, struct {
		ID encodable.Bytes `json:"id"`
	}{ID: pubID})
}

func createUser(db model.Provider, kvs kvstor.Provider, emailer smtp.SendEmailer, user User) ([]byte, *serverError) {
	user.Username = strings.ToLower(strings.TrimSpace(user.Username))
	if user.Username == "" {
		return nil, &serverError{code: errorInvalidUsername, message: "Username can not be empty"}
	}
	user.Username = strings.ToLower(user.Username)
	if len(user.Username) > 32 {
		return nil, &serverError{code: errorInvalidUsername, message: "Username must be less than 33 characters."}
	}
	if !validUsernamePattern.MatchString(user.Username) {
		return nil, &serverError{code: errorInvalidUsername, message: "Usernames must be at least 5 characters long and may only contain lowercase letters (a-z) or numbers (0-9)."}
	}
	if len(user.PasswordSalt) == 0 {
		return nil, &serverError{code: errorInvalidPasswordSalt, message: "Invalid password salt"}
	}
	var alg sodium.Algorithm
	switch user.PasswordHashAlgorithm {
	case sodium.Argon2i13.Name:
		alg = sodium.Argon2i13
	case sodium.Argon2id13.Name:
		alg = sodium.Argon2id13
	default:
		return nil, &serverError{code: errorInvalidPasswordHashAlgorithm, message: "Invalid password hash algorithm"}
	}
	if user.PasswordHashOperationsLimit < alg.OpsLimitInteractive {
		return nil, &serverError{code: errorArgon2iOpsLimitTooLow, message: "Password hash ops limit is too low"}
	}
	if user.PasswordHashMemoryLimit < alg.MemLimitInteractive {
		return nil, &serverError{code: errorArgon2iMemLimitTooLow, message: "Password hash mem limit is too low"}
	}
	if user.PublicKey == nil || len(user.PublicKey) != sodium.PublicKeySize {
		return nil, &serverError{
			code:    errorInvalidPublicKey,
			message: fmt.Sprintf("Invalid public key. Expected %d bytes. Found %d.", sodium.PublicKeySize, len(user.PublicKey)),
		}
	}
	if len(user.WrappedSecretKey) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSecretKey, message: "Invalid wrapped secret key"}
	}
	if len(user.WrappedSecretKeyNonce) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSecretKeyNonce, message: "Invalid wrapped secret key nonce"}
	}
	if len(user.WrappedSymmetricKey) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSymmetricKey, message: "Invalid wrapped symmetric key"}
	}
	if len(user.WrappedSymmetricKeyNonce) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSymmetricKeyNonce, message: "Invalid wrapped symmetric key nonce"}
	}
	user.Email = strings.TrimSpace(strings.ToLower(user.Email))
	var emailVerificationToken *string
	if user.Email != "" {
		if len(user.Email) > 254 {
			return nil, &serverError{code: errorInvalidEmail, message: "Email address is too long"}
		}
		parts := strings.Split(user.Email, "@")
		if len(parts) != 2 {
			return nil, &serverError{code: errorInvalidEmail, message: "Email address doesn't have a user and domain separated by an '@'"}
		}
		if parts[0] == "" {
			return nil, &serverError{code: errorInvalidEmail, message: "Invalid local component in email"}
		}
		domainParts := strings.Split(parts[1], ".")
		if len(domainParts) < 2 {
			return nil, &serverError{code: errorInvalidEmail, message: "Invalid domain in email address"}
		}
		tld := domainParts[len(domainParts)-1]
		if len(tld) < 2 {
			return nil, &serverError{code: errorInvalidEmail, message: "Invalid tld in domain"}
		}

		// everything looks good, so let's generate a verification token
		token := base62.Rand(16)
		emailVerificationToken = &token
	}

	// check if the username is already in use
	available, err := db.UsernameAvailable(user.Username)
	if err != nil {
		log.Err(err).Msg("db.UsernameAvailable")
		return nil, newInternalErr()
	}
	if !available {
		return nil, &serverError{code: errorUsernameNotAvailable, message: "That username is already in use"}
	}

	userRec := model.UserRecord{
		Username:                    user.Username,
		PasswordSalt:                user.PasswordSalt,
		PasswordHashAlgorithm:       user.PasswordHashAlgorithm,
		PasswordHashOperationsLimit: user.PasswordHashOperationsLimit,
		PasswordHashMemoryLimit:     user.PasswordHashMemoryLimit,
		PublicKey:                   user.PublicKey,
		WrappedSecretKey:            user.WrappedSecretKey,
		WrappedSecretKeyNonce:       user.WrappedSecretKeyNonce,
		WrappedSymmetricKey:         user.WrappedSymmetricKey,
		WrappedSymmetricKeyNonce:    user.WrappedSymmetricKeyNonce,
		Email:                       &user.Email,
	}
	id, err := db.InsertUser(userRec, emailVerificationToken)
	if err != nil {
		log.Err(err).Msg("db.InsertUser")
		return nil, newInternalErr()
	}

	// create an id for public use
	pubID := make([]byte, publicUserIDSize)
	idExists := true

	for idExists {
		_, err = crand.Read(pubID)
		if err != nil {
			log.Err(err).Msg("crand.Read")
			return nil, newInternalErr()
		}

		// check if the id already exists
		val, err := kvs.UserIDFromPublicID(pubID)
		if err != nil {
			log.Err(err).Msg("kvs.UserIDFromPublicID")
			return nil, newInternalErr()
		}
		if val > 0 {
			// someone already has this public id, let's try again
			continue
		}
		idExists = false

		err = kvs.InsertIds(id, pubID)
		if err != nil {
			log.Err(err).Msg("kvs.InsertIds")
			return nil, newInternalErr()
		}
	}

	if emailVerificationToken != nil {
		go func() {
			err = sendVerificationEmail(*emailVerificationToken, user.Email, emailer)
			if err != nil {
				log.Err(err).Msg("sending the verification email")
			}
		}()
	}

	return pubID, nil
}

// getUserPublicKeyHandler handles GET /users/{public_id}/public-key
func getUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		sendNotFound(w, "user not found", errorUserNotFound)
		return
	}

	db := providersCtx(r.Context()).db
	pubKey, err := db.UserPublicKey(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	resp := struct {
		PublicKey encodable.Bytes `json:"public_key"`
	}{PublicKey: pubKey}

	sendSuccess(w, resp)
}

// searchUsersHandler handles GET /users
func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	username = strings.TrimSpace(username)
	username = strings.ToLower(username)

	user := User{}
	var err error
	providers := providersCtx(r.Context())
	db := providers.db
	user.ID, user.PublicKey, err = db.LimitedUserInfo(username)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if user.PublicKey == nil {
		sendNotFound(w, "user not found", errorUserNotFound)
		return
	}

	user.Username = username
	kvs := providers.kvs
	user.PublicID, err = kvs.PublicIDFromUserID(user.ID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	sendSuccess(w, user)
}

func getUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseUserID(w, r)
	if !ok {
		return
	}

	db := providersCtx(r.Context()).db
	username, pubKey, err := db.LimitedUserInfoID(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	// don't need to check for a missing user, because parseUserID ensures the user exists
	user := User{
		Username:  username,
		PublicKey: pubKey,
	}

	sendSuccess(w, user)
}
