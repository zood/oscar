package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/smtp"
	"zood.xyz/oscar/sodium"

	"zood.xyz/oscar/boltdb"
	"zood.xyz/oscar/sqlite"
)

func TestCreateUserNoEmail(t *testing.T) {
	db, _ := sqlite.New(sqlite.InMemoryDSN)
	kvs := boltdb.Temp(t)

	user := User{Username: "Arash"}
	salt := make([]byte, sodium.PasswordStretchingSaltSize)
	sodium.Random(salt)
	user.PasswordHashAlgorithm = sodium.Argon2id13.Name
	user.PasswordHashMemoryLimit = sodium.Argon2id13.MemLimitInteractive
	user.PasswordHashOperationsLimit = sodium.Argon2id13.OpsLimitInteractive
	user.PasswordSalt = salt

	kp, _ := sodium.NewKeyPair()
	user.PublicKey = kp.Public
	user.WrappedSecretKey = []byte("wrapped-secret-key")
	user.WrappedSecretKeyNonce = []byte("wrapped-secret-key-nonce")
	user.WrappedSymmetricKey = []byte("wrapped-symmetric-key")
	user.WrappedSymmetricKeyNonce = []byte("wrapped-symmetric-key-nonce")

	emailWasSent := false
	var sendEmail smtp.SendEmailFunc
	sendEmail = func(from string, to string, subj string, textMsg string, htmlMsg *string) error {
		emailWasSent = true
		return nil
	}

	pubID, serr := createUser(db, kvs, sendEmail, user)
	if serr != nil {
		t.Fatal(serr)
	}
	if len(pubID) != publicUserIDSize {
		t.Fatalf("Invalid pub id size. Got %d", len(pubID))
	}
	// sleep for 50ms to see if the goroutine tries to send an email
	time.Sleep(50 * time.Millisecond)
	if emailWasSent {
		t.Fatal("An email should not have been sent. No address was provided")
	}
	// make sure the user exists in the db
	arash, err := db.User(strings.ToLower(user.Username))
	if err != nil {
		t.Fatal(err)
	}
	if arash == nil {
		t.Fatal("didn't find user")
	}
	userID, err := kvs.UserIDFromPublicID(pubID)
	if err != nil {
		t.Fatal(err)
	}
	if userID < 1 {
		t.Fatalf("Didn't get a valid user id: %d", userID)
	}
}

func TestCreateUserWithEmail(t *testing.T) {
	db, _ := sqlite.New(sqlite.InMemoryDSN)
	kvs := boltdb.Temp(t)

	user := User{
		Username: "Arash",
		Email:    "bobvance@vancerefrigeration.com",
	}
	salt := make([]byte, sodium.PasswordStretchingSaltSize)
	sodium.Random(salt)
	user.PasswordHashAlgorithm = sodium.Argon2id13.Name
	user.PasswordHashMemoryLimit = sodium.Argon2id13.MemLimitInteractive
	user.PasswordHashOperationsLimit = sodium.Argon2id13.OpsLimitInteractive
	user.PasswordSalt = salt

	kp, _ := sodium.NewKeyPair()
	user.PublicKey = kp.Public
	user.WrappedSecretKey = []byte("wrapped-secret-key")
	user.WrappedSecretKeyNonce = []byte("wrapped-secret-key-nonce")
	user.WrappedSymmetricKey = []byte("wrapped-symmetric-key")
	user.WrappedSymmetricKeyNonce = []byte("wrapped-symmetric-key-nonce")

	emailWasSent := false
	var sendEmail smtp.SendEmailFunc
	sendEmail = func(from string, to string, subj string, textMsg string, htmlMsg *string) error {
		emailWasSent = true
		return nil
	}

	pubID, serr := createUser(db, kvs, sendEmail, user)
	if serr != nil {
		t.Fatal(serr)
	}
	if len(pubID) != publicUserIDSize {
		t.Fatalf("Invalid pub id size. Got %d", len(pubID))
	}
	// sleep for 50ms to allow the goroutine to send the email
	time.Sleep(50 * time.Millisecond)
	if !emailWasSent {
		t.Fatal("An email should have been sent")
	}

	// make sure the user exists in the db
	arash, err := db.User(strings.ToLower(user.Username))
	if err != nil {
		t.Fatal(err)
	}
	if arash == nil {
		t.Fatal("didn't find user")
	}
	userID, err := kvs.UserIDFromPublicID(pubID)
	if err != nil {
		t.Fatal(err)
	}
	if userID < 1 {
		t.Fatalf("Didn't get a valid user id: %d", userID)
	}
}

func TestCreateUserHandler(t *testing.T) {
	user := User{Username: "Arash"}
	salt := make([]byte, sodium.PasswordStretchingSaltSize)
	sodium.Random(salt)
	user.PasswordHashAlgorithm = sodium.Argon2id13.Name
	user.PasswordHashMemoryLimit = sodium.Argon2id13.MemLimitInteractive
	user.PasswordHashOperationsLimit = sodium.Argon2id13.OpsLimitInteractive
	user.PasswordSalt = salt

	kp, _ := sodium.NewKeyPair()
	user.PublicKey = kp.Public
	user.WrappedSecretKey = []byte("wrapped-secret-key")
	user.WrappedSecretKeyNonce = []byte("wrapped-secret-key-nonce")
	user.WrappedSymmetricKey = []byte("wrapped-symmetric-key")
	user.WrappedSymmetricKeyNonce = []byte("wrapped-symmetric-key-nonce")

	db, _ := sqlite.New(sqlite.InMemoryDSN)
	kvs := boltdb.Temp(t)
	var sendEmail smtp.SendEmailFunc = func(from string, to string, subj string, textMsg string, htmlMsg *string) error {
		return nil
	}

	data, _ := json.Marshal(user)
	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(data))
	ctx := context.WithValue(r.Context(), contextRelationalStorageProviderKey, db)
	ctx = context.WithValue(ctx, contextKeyValueProviderKey, kvs)
	ctx = context.WithValue(ctx, contextSendEmailerKey, sendEmail)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	createUserHandler(w, r)

	resp := struct {
		ID encodable.Bytes `json:"id"`
	}{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID == nil {
		t.Fatal("did not receive a public id")
	}
	if len(resp.ID) != publicUserIDSize {
		t.Fatalf("user id is the wrong size (%d). Got %s", len(resp.ID), hex.EncodeToString(resp.ID))
	}

	arash, err := db.User(strings.ToLower(user.Username))
	if err != nil {
		t.Fatal(err)
	}
	if arash == nil {
		t.Fatal("user not found")
	}
	uid, err := kvs.UserIDFromPublicID(resp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if uid < 1 {
		t.Fatal("invalid user id")
	}
	if arash.ID != uid {
		t.Fatalf("user id mismatch: %d != %d", arash.ID, uid)
	}
}
