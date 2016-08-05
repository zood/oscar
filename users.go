package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

// User ...
type User struct {
	ID                       int
	Username                 string
	PasswordSalt             []byte
	PublicKey                []byte
	WrappedSecretKey         []byte
	WrappedSecretKeyNonce    []byte
	WrappedSymmetricKey      []byte
	WrappedSymmetricKeyNonce []byte
}

// CreateUserHandler handles POST /users
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Username                 string `json:"username"`
		PasswordSalt             string `json:"password_salt"`
		PublicKey                string `json:"public_key"`
		WrappedSecretKey         string `json:"wrapped_secret_key"`
		WrappedSecretKeyNonce    string `json:"wrapped_secret_key_nonce"`
		WrappedSymmetricKey      string `json:"wrapped_symmetric_key"`
		WrappedSymmetricKeyNonce string `json:"wrapped_symmetric_key_nonce"`
	}{}

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&body)
	if err != nil {
		log.Printf("can't parse body: " + err.Error())
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	user := User{Username: body.Username}
	user.PasswordSalt, err = hex.DecodeString(body.PasswordSalt)
	if err != nil {
		sendBadReq(w, "unable to decode 'password' salt' field from base64: "+err.Error())
		return
	}
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

	userID, sErr := createUser(user)
	if sErr != nil {
		if sErr.code == ErrorInternal {
			sendInternalErr(w, err)
		} else {
			sendBadReqCode(w, sErr.message, sErr.code)
		}
		return
	}

	token, err := newAccessToken(userID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"user_id":      userID,
		"access_token": token,
	})
}

func createUser(user User) (int, *serverError) {
	if user.Username == "" {
		return 0, &serverError{code: ErrorInvalidUsername, message: "Username can not be empty"}
	}
	if user.PasswordSalt == nil || len(user.PasswordSalt) == 0 {
		return 0, &serverError{code: ErrorInvalidPasswordSalt, message: "Invalid password salt"}
	}
	if user.PublicKey == nil || len(user.PublicKey) != publicKeySize {
		return 0, &serverError{code: ErrorInvalidPublicKey, message: "Invalid public key"}
	}
	if user.WrappedSecretKey == nil || len(user.WrappedSecretKey) == 0 {
		return 0, &serverError{code: ErrorInvalidWrappedSecretKey, message: "Invalid wrapped secret key"}
	}
	if user.WrappedSecretKeyNonce == nil || len(user.WrappedSecretKeyNonce) == 0 {
		return 0, &serverError{code: ErrorInvalidWrappedSecretKeyNonce, message: "Invalid wrapped secret key nonce"}
	}
	if user.WrappedSymmetricKey == nil || len(user.WrappedSymmetricKey) == 0 {
		return 0, &serverError{code: ErrorInvalidWrappedSymmetricKey, message: "Invalid wrapped symmetric key"}
	}
	if user.WrappedSymmetricKeyNonce == nil || len(user.WrappedSymmetricKeyNonce) == 0 {
		return 0, &serverError{code: ErrorInvalidWrappedSymmetricKeyNonce, message: "Invalid wrapped symmetric key nonce"}
	}

	// check if the username is already in use
	checkUsernameSQL := "SELECT id FROM users WHERE username=?"
	var foundID int
	err := db().QueryRow(checkUsernameSQL, user.Username).Scan(&foundID)
	if err == nil {
		return 0, &serverError{code: ErrorUsernameNotAvailable, message: "That username is already in use"}
	}

	insertSQL := `
	INSERT INTO users (	username,
						password_salt,
		 				public_key,
						wrapped_secret_key,
						wrapped_secret_key_nonce,
						wrapped_symmetric_key,
						wrapped_symmetric_key_nonce)
						VALUES (?, ?, ?, ?, ?, ?, ?)`
	result, err := db().Exec(insertSQL, user.Username, user.PasswordSalt, user.PublicKey, user.WrappedSecretKey, user.WrappedSecretKeyNonce, user.WrappedSymmetricKey, user.WrappedSymmetricKeyNonce)
	if err != nil {
		logErr(err)
		return 0, &serverError{code: ErrorInternal, message: "Internal server error"}
	}

	id, err := result.LastInsertId()
	if err != nil {
		logErr(err)
		return 0, &serverError{code: ErrorInternal, message: "Internal server error"}
	}

	return int(id), nil
}
