package main

import (
	"bytes"
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
	"zood.dev/oscar/kvstor"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

func createTestUser(t *testing.T, db sqlite.DB, kvs kvstor.Provider) (User, sodium.KeyPair) {
	t.Helper()

	username := strings.ToLower(base62.Rand(8))
	keyPair, err := sodium.NewKeyPair()
	require.NoError(t, err)

	passwordSalt := make([]byte, sodium.PasswordStretchingSaltSize)
	sodium.Random(passwordSalt)
	symKey := make([]byte, sodium.SymmetricKeySize)
	sodium.Random(symKey)
	user := User{
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
	pubID, sErr := createUser(db, kvs, smtp.NewMockSendEmailer(), user)
	require.Nil(t, sErr)

	user.PublicID = pubID
	user.ID, err = kvs.UserIDFromPublicID(pubID)
	require.NoError(t, err)

	return user, keyPair
}

func TestCreateUserNoEmail(t *testing.T) {
	db := sqlite.NewMockDB(t)
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
	db := sqlite.NewMockDB(t)
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
	api := testHTTPAPI(t)
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
	w := httptest.NewRecorder()

	api.createUser(w, r)

	resp := struct {
		ID encodable.Bytes `json:"id"`
	}{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.NotNil(t, resp.ID, "expected a public id")
	require.Len(t, resp.ID, publicUserIDSize, "user id size")

	arash, err := api.db.User(strings.ToLower(user.Username))
	require.NoError(t, err)
	require.NotNil(t, arash, "user not found")

	uid, err := api.kvs.UserIDFromPublicID(resp.ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, uid, int64(1), "invalid user id")
	require.Equal(t, arash.ID, uid, "ids should match after retrieval")
}

func TestDeleteUser(t *testing.T) {
	api := testHTTPAPI(t)

	userA, keyPairA := createTestUser(t, api.db, api.kvs)
	userB, _ := createTestUser(t, api.db, api.kvs)

	hndlr := newOscarRouter(api)

	srvr := httptest.NewServer(hndlr)
	defer srvr.Close()

	accessToken := loginTestUser(t, api, userA, keyPairA)

	r := httptest.NewRequest(http.MethodDelete, srvr.URL+"/1/users/me", nil)
	r.Header.Set("X-Oscar-Access-Token", accessToken)
	w := httptest.NewRecorder()

	hndlr.ServeHTTP(w, r)

	// make sure user A is gone
	actualUserA, err := api.db.User(userA.Username)
	require.NoError(t, err)
	require.Nil(t, actualUserA)

	// make sure user B is still present
	actualUserB, err := api.db.User(userB.Username)
	require.NoError(t, err)
	require.Equal(t, userB.ID, actualUserB.ID)
}
