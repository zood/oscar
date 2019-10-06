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

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/base62"
	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/encodable"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

func createTestUser(t *testing.T, providers *serverProviders) (user User, keyPair sodium.KeyPair) {
	t.Helper()

	username := strings.ToLower(base62.Rand(8))
	var err error
	keyPair, err = sodium.NewKeyPair()
	require.NoError(t, err)

	passwordSalt := make([]byte, sodium.PasswordStretchingSaltSize)
	sodium.Random(passwordSalt)
	symKey := make([]byte, sodium.SymmetricKeySize)
	sodium.Random(symKey)
	user = User{
		Email:                       "",
		PasswordHashAlgorithm:       sodium.Argon2id13.Name,
		PasswordHashMemoryLimit:     sodium.Argon2id13.MemLimitInteractive,
		PasswordHashOperationsLimit: sodium.Argon2id13.OpsLimitInteractive,
		PasswordSalt:                passwordSalt,
		PublicKey:                   keyPair.Public,
		Username:                    username,
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-key"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
	}
	pubID, sErr := createUser(providers.db, providers.kvs, smtp.NewMockSendEmailer(), user)
	require.Nil(t, sErr)

	user.PublicID = pubID
	user.ID, err = providers.kvs.UserIDFromPublicID(pubID)
	require.NoError(t, err)

	return
}

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

	emailer := smtp.NewMockSendEmailer()

	pubID, serr := createUser(db, kvs, emailer, user)
	if serr != nil {
		t.Fatal(serr)
	}
	if len(pubID) != publicUserIDSize {
		t.Fatalf("Invalid pub id size. Got %d", len(pubID))
	}
	// sleep for 50ms to see if the goroutine tries to send an email
	time.Sleep(50 * time.Millisecond)
	if emailer.SentEmail {
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

	emailer := smtp.NewMockSendEmailer()

	pubID, serr := createUser(db, kvs, emailer, user)
	if serr != nil {
		t.Fatal(serr)
	}
	if len(pubID) != publicUserIDSize {
		t.Fatalf("Invalid pub id size. Got %d", len(pubID))
	}
	// sleep for 50ms to allow the goroutine to send the email
	time.Sleep(50 * time.Millisecond)
	if !emailer.SentEmail {
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
	providers := createTestProviders(t)
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

	data, _ := json.Marshal(user)
	r := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(data))
	ctx := context.WithValue(r.Context(), contextServerProvidersKey, providers)
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

	arash, err := providers.db.User(strings.ToLower(user.Username))
	if err != nil {
		t.Fatal(err)
	}
	if arash == nil {
		t.Fatal("user not found")
	}
	uid, err := providers.kvs.UserIDFromPublicID(resp.ID)
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
