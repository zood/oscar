package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"pijun.io/oscar/relstor"

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
	PasswordHashAlgorithm       string         `json:"password_hash_algorithm" db:"password_hash_algorithm"`
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
		sendNotFound(w, fmt.Sprintf("user '%s' not found", pubIDStr), errorUserNotFound)
		return 0, false
	}

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
	log.Printf("createUserHandler")
	user := User{}
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	log.Printf("calling createUser...")
	pubID, sErr := createUser(user)
	if sErr != nil {
		log.Printf("createUser had an error: %v", sErr)
		if sErr.code == errorInternal {
			sendInternalErr(w, err)
		} else {
			sendBadReqCode(w, sErr.message, sErr.code)
		}
		return
	}

	log.Printf("createUser - sending success")
	sendSuccess(w, struct {
		ID encodableBytes `json:"id"`
	}{ID: pubID})
	log.Printf("createUser - success sent")
}

func createUser(user User) ([]byte, *serverError) {
	user.Username = strings.ToLower(strings.TrimSpace(user.Username))
	if user.Username == "" {
		return nil, &serverError{code: errorInvalidUsername, message: "Username can not be empty"}
	}
	if len(user.Username) > 32 {
		return nil, &serverError{code: errorInvalidUsername, message: "Username must be less than 33 characters."}
	}
	if !validUsernamePattern.MatchString(user.Username) {
		return nil, &serverError{code: errorInvalidUsername, message: "Usernames must be at least 5 characters long and may only contain letters (a-z) or numbers (0-9)."}
	}
	if user.PasswordSalt == nil || len(user.PasswordSalt) == 0 {
		return nil, &serverError{code: errorInvalidPasswordSalt, message: "Invalid password salt"}
	}
	if user.PasswordHashAlgorithm != hashAlgArgon2i13 && user.PasswordHashAlgorithm != hashAlgArgon2id13 {
		return nil, &serverError{code: errorInvalidPasswordHashAlgorithm, message: "Invalid password hash algorithm"}
	}
	if user.PasswordHashOperationsLimit < argon2iOpsLimitInteractive {
		return nil, &serverError{code: errorArgon2iOpsLimitTooLow, message: "Password hash ops limit is too low"}
	}
	if user.PasswordHashMemoryLimit < argon2iMemLimitInteractive {
		return nil, &serverError{code: errorArgon2iMemLimitTooLow, message: "Password hash mem limit is too low"}
	}
	if user.PublicKey == nil || len(user.PublicKey) != publicKeySize {
		return nil, &serverError{
			code:    errorInvalidPublicKey,
			message: fmt.Sprintf("Invalid public key. Expected %d bytes. Found %d.", publicKeySize, len(user.PublicKey)),
		}
	}
	if user.WrappedSecretKey == nil || len(user.WrappedSecretKey) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSecretKey, message: "Invalid wrapped secret key"}
	}
	if user.WrappedSecretKeyNonce == nil || len(user.WrappedSecretKeyNonce) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSecretKeyNonce, message: "Invalid wrapped secret key nonce"}
	}
	if user.WrappedSymmetricKey == nil || len(user.WrappedSymmetricKey) == 0 {
		return nil, &serverError{code: errorInvalidWrappedSymmetricKey, message: "Invalid wrapped symmetric key"}
	}
	if user.WrappedSymmetricKeyNonce == nil || len(user.WrappedSymmetricKeyNonce) == 0 {
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
		token := randBase62(16)
		emailVerificationToken = &token
	}

	// check if the username is already in use
	available, err := rs.UsernameAvailable(user.Username)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}
	if !available {
		return nil, &serverError{code: errorUsernameNotAvailable, message: "That username is already in use"}
	}

	userRec := relstor.UserRecord{
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
		Email: &user.Email,
	}
	id, err := rs.InsertUser(userRec, emailVerificationToken)
	if err != nil {
		logErr(err)
		return nil, newInternalErr()
	}

	// create an id for public use
	pubID := make([]byte, publicUserIDSize)
	idExists := true

	for idExists {
		_, err = crand.Read(pubID)
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}

		// check if the id already exists
		val, err := kvs.UserIDFromPublicID(pubID)
		if err != nil {
			logErr(err)
			return nil, newInternalErr()
		}
		if val < 1 {
			// someone already has this public id, let's try again
			continue
		}
		idExists = false

		err = kvs.InsertIds(id, pubID)
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

	pubKey, err := rs.UserPublicKey(userID)
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
	var err error
	user.ID, user.PublicKey, err = rs.LimitedUserInfo(username)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if user.PublicKey == nil {
		sendNotFound(w, "user not found", errorUserNotFound)
		return
	}

	user.Username = username
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

	username, pubKey, err := rs.LimitedUserInfoID(userID)
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

// only useful for logging
// func usernameFromID(userID int64) string {
// 	var str sql.NullString
// 	err := db().QueryRow("SELECT username FROM users WHERE id=?", userID).Scan(&str)
// 	if err != nil {
// 		return ""
// 	}
// 	return str.String
// }
