package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/encodable"
	"zood.dev/oscar/model"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

func loginTestUser(t *testing.T, providers *serverProviders, user User, userKeyPair sodium.KeyPair) (accessToken string) {
	t.Helper()

	creationDate := time.Now().Unix()
	challenge := make([]byte, 255)
	crand.Read(challenge)

	cdCT, cdNonce, err := sodium.PublicKeyEncrypt(int64ToBytes(creationDate), providers.keyPair.Public, userKeyPair.Secret)
	require.NoError(t, err)

	token := sessionToken{
		Name:                  user.Username,
		CreationDate:          creationDate,
		EncryptedCreationDate: append(cdNonce, cdCT...),
	}
	tokenBytes, err := json.Marshal(token)
	require.NoError(t, err)
	tokenCT, tokeNonce, err := sodium.SymmetricKeyEncrypt(tokenBytes, providers.symKey)
	require.NoError(t, err)
	accessTokenBytes := append(tokeNonce, tokenCT...)
	accessToken = base64.StdEncoding.EncodeToString(accessTokenBytes)
	providers.db.InsertAccessToken(accessToken, user.ID, time.Now().Add(24*time.Hour).Unix())
	return
}

func TestCreateTicketHandler(t *testing.T) {
	db, _ := sqlite.New(sqlite.InMemoryDSN)
	var userID int64 = 34

	r := httptest.NewRequest(http.MethodPost, "/sessions/expiring-tickets", nil)
	ctx := context.WithValue(r.Context(), contextUserIDKey, userID)
	providers := &serverProviders{
		db: db,
	}
	ctx = context.WithValue(ctx, contextServerProvidersKey, providers)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()

	createTicketHandler(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200. Got %d: %s", w.Code, w.Body.Bytes())
	}

	respBody := struct {
		Ticket string `json:"ticket"`
	}{}
	if err := json.Unmarshal(w.Body.Bytes(), &respBody); err != nil {
		t.Fatal(err)
	}

	if len(respBody.Ticket) != ticketLength {
		t.Fatalf("Incorrect ticket size. Expected %d, got %d", ticketLength, len(respBody.Ticket))
	}

	// make sure it's in the database
	retrieved, _, _ := db.Ticket(respBody.Ticket)
	if retrieved != userID {
		t.Fatalf("ticket not found or wrong user id. Got %d", retrieved)
	}
}

func TestVerifySessionTicket(t *testing.T) {
	db, _ := sqlite.New(sqlite.InMemoryDSN)

	userID, err := verifySessionTicket(db, "")
	if err != nil {
		t.Fatal(err)
	}
	if userID != 0 {
		t.Fatalf("Should not have found user. Got %d", userID)
	}

	// put a valid token in there
	ticket := "deadbeeffeebdaed"
	var expectedUserID int64 = 19
	db.InsertTicket(ticket, expectedUserID)

	userID, err = verifySessionTicket(db, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if userID != expectedUserID {
		t.Fatalf("user id mismatch: %d != %d", userID, expectedUserID)
	}

	ticket = "anotherticket"
	expectedUserID = 24
	db.InsertTicket(ticket, expectedUserID)
	// manually change the timestamp to something older
	sqldb := db.(sqlite.Databaser).Database()
	_, err = sqldb.Exec(`UPDATE tickets SET timestamp=? WHERE ticket=?`, time.Now().Unix()-120, ticket)
	if err != nil {
		t.Fatal(err)
	}

	userID, err = verifySessionTicket(db, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if userID != 0 {
		t.Fatalf("User id should not have matched. Got %d", userID)
	}
}

func TestCreateAuthChallengeHandler(t *testing.T) {
	providers := createTestProviders(t)
	user, _ := createTestUser(t, providers)

	r := httptest.NewRequest(http.MethodPost, "/1/sessions/"+user.Username+"/challenge", nil)
	w := httptest.NewRecorder()

	router := newOscarRouter(providers)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200. Got %d: %s", w.Code, w.Body.Bytes())
	}

	resp := struct {
		User         User            `json:"user"`
		Challenge    encodable.Bytes `json:"challenge"`
		CreationDate encodable.Bytes `json:"creation_date"`
	}{}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if len(resp.Challenge) == 0 {
		t.Fatal("Missing challenge")
	}
	if len(resp.User.PublicKey) != sodium.PublicKeySize {
		t.Fatalf("Incorrect public key lenth. Should be %d, got %d", sodium.PublicKeySize, len(resp.User.PublicKey))
	}
	if !bytes.Equal(resp.User.WrappedSecretKey, user.WrappedSecretKey) {
		t.Fatal("wrapped secret key mismatch")
	}
	if !bytes.Equal(resp.User.WrappedSecretKeyNonce, user.WrappedSecretKeyNonce) {
		t.Fatal("wrapped secret key nonce mismatch")
	}
	if !bytes.Equal(resp.User.PasswordSalt, user.PasswordSalt) {
		t.Fatal("password salt mismatch")
	}
	if resp.User.PasswordHashAlgorithm != user.PasswordHashAlgorithm {
		t.Fatalf("pwd hash alg mismatch: %s != %s", resp.User.PasswordHashAlgorithm, user.PasswordHashAlgorithm)
	}
	if resp.User.PasswordHashOperationsLimit != user.PasswordHashOperationsLimit {
		t.Fatalf("ops limit mismatch: %d != %d", resp.User.PasswordHashOperationsLimit, user.PasswordHashOperationsLimit)
	}
	if resp.User.PasswordHashMemoryLimit != user.PasswordHashMemoryLimit {
		t.Fatalf("mem limit mismatch: %d != %d", resp.User.PasswordHashMemoryLimit, user.PasswordHashMemoryLimit)
	}

	// make sure the same challenge exists in the database
	challenge, err := providers.db.SessionChallenge(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if challenge == nil {
		t.Fatal("Did not find challenge in the database")
	}
	// should be a recent creation date
	now := time.Now().Unix()
	if challenge.CreationDate < now-5 {
		t.Fatalf("creation date is too old. Found %d, currently %d", challenge.CreationDate, now-5)
	}
	if !bytes.Equal(resp.CreationDate, int64ToBytes(challenge.CreationDate)) {
		t.Fatalf("creation date mismatch")
	}
	if !bytes.Equal(challenge.Challenge, resp.Challenge) {
		t.Fatalf("db challenge differs from received challenge")
	}

	// Check for a 404 when an invalid/unknown username is given
	r = httptest.NewRequest(http.MethodPost, "/1/sessions/foo/challenge", nil)
	w = httptest.NewRecorder()

	router.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("Expected 404. Got %d: %s", w.Code, w.Body.Bytes())
	}
}

func TestFinishAuthChallengeHandler(t *testing.T) {
	providers := createTestProviders(t)

	user, keyPair := createTestUser(t, providers)

	challenge := make([]byte, 255)
	crand.Read(challenge)
	creationDate := time.Now().Unix()
	providers.db.InsertSessionChallenge(user.ID, creationDate, challenge)

	challengeCT, challengeNonce, _ := sodium.PublicKeyEncrypt(challenge, providers.keyPair.Public, keyPair.Secret)
	cdCT, cdNonce, _ := sodium.PublicKeyEncrypt(int64ToBytes(creationDate), providers.keyPair.Public, keyPair.Secret)

	body := struct {
		Challenge    encryptedData `json:"challenge"`
		CreationDate encryptedData `json:"creation_date"`
	}{
		Challenge: encryptedData{
			CipherText: challengeCT,
			Nonce:      challengeNonce,
		},
		CreationDate: encryptedData{
			CipherText: cdCT,
			Nonce:      cdNonce,
		},
	}

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost,
		"/1/sessions/"+user.Username+"/challenge-response",
		bytes.NewReader(data))
	w := httptest.NewRecorder()

	router := newOscarRouter(providers)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200. Got %d: %s", w.Code, w.Body.Bytes())
	}

	lr := loginResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &lr); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(lr.ID, user.PublicID) {
		t.Fatal("public id mismatch")
	}
	if !bytes.Equal(lr.WrappedSymmetricKey, user.WrappedSymmetricKey) {
		t.Fatal("wrapped sym key mismatch")
	}
	if !bytes.Equal(lr.WrappedSymmetricKeyNonce, user.WrappedSymmetricKeyNonce) {
		t.Fatal("wrapped sym key nonce mismatch")
	}

	// the access token should be base64. try to decode it to verify
	encdToken, err := base64.StdEncoding.DecodeString(lr.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	// decrypt the bytes
	msg, success := sodium.SymmetricKeyDecrypt(encdToken[sodium.SymmetricNonceSize:], encdToken[:sodium.SymmetricNonceSize], providers.symKey)
	if !success {
		t.Fatal("failed to decrypt session token")
	}

	st := sessionToken{}
	if err = json.Unmarshal(msg, &st); err != nil {
		t.Fatal(err)
	}

	if st.CreationDate != creationDate {
		t.Fatalf("creationDate mismatch: %d != %d", st.CreationDate, creationDate)
	}

	if st.Name != user.Username {
		t.Fatalf("token name mismatch: %s != %s", st.Name, user.Username)
	}

	// 404 for an invalid/unknown username
	r = httptest.NewRequest(http.MethodPost, "/1/sessions/foo/challenge-response", bytes.NewReader(data))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("Expected 404. Got %d: %s", w.Code, w.Body.Bytes())
	}
}

func TestVerifyAccessToken(t *testing.T) {
	db := sqlite.NewMockDB(t)

	// Test verification with no token in the database
	actual, err := verifyAccessToken(db, "not-a-token")
	require.NoError(t, err)
	require.Zero(t, actual)

	// Test that present tokens are properly verified
	atr := model.AccessTokenRecord{
		Token:     "dadadaalalalal",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		UserID:    15,
	}
	err = db.InsertAccessToken(atr.Token, atr.UserID, atr.ExpiresAt)
	require.NoError(t, err)

	actual, err = verifyAccessToken(db, atr.Token)
	require.NoError(t, err)
	require.Equal(t, atr.UserID, actual)

	// Test verification with an expired token
	atr = model.AccessTokenRecord{
		Token:     "13907ufjh",
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		UserID:    20,
	}
	err = db.InsertAccessToken(atr.Token, atr.UserID, atr.ExpiresAt)
	require.NoError(t, err)

	actual, err = verifyAccessToken(db, atr.Token)
	require.NoError(t, err)
	require.Zero(t, actual)
}

func TestSessionHandler(t *testing.T) {
	data := []byte("success")
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
	providers := createTestProviders(t)
	user, keyPair := createTestUser(t, providers)
	token := loginTestUser(t, providers, user, keyPair)
	wrappedFn := sessionHandler(fn)

	r := httptest.NewRequest(http.MethodGet, "/1/test", nil)
	r.Header.Set("X-Oscar-Access-Token", token)
	ctx := context.WithValue(r.Context(), contextServerProvidersKey, providers)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	wrappedFn.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code, "Got: %s", w.Body.Bytes())
	require.Equal(t, data, w.Body.Bytes())

	// make sure we get an error for an invalid token
	// reuse the request
	r.Header.Set("X-Oscar-Access-Token", "not-a-valid-token")
	w = httptest.NewRecorder()
	wrappedFn.ServeHTTP(w, r)

	require.Equal(t, http.StatusUnauthorized, w.Code, "Got: %s", w.Body.Bytes())
}
