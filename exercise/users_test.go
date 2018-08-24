package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"zood.xyz/oscar/base62"
	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/sodium"
)

type testUser struct {
	publicID                      []byte
	username                      string
	password                      string
	keyPair                       sodium.KeyPair
	passwordHashAlg               sodium.Algorithm
	passwordHashOpsLimit          uint
	passwordHashMemLimit          uint64
	passwordHash                  []byte
	passwordSalt                  []byte
	symmetricKey                  []byte
	wrappedSymmetricKeyCipherText []byte
	wrappedSymmetricKeyNonce      []byte
	wrappedSecretKeyCipherText    []byte
	wrappedSecretKeyNonce         []byte
}

func (tu testUser) userReader() io.Reader {
	body := struct {
		Username                    string          `json:"username"`
		PasswordSalt                encodable.Bytes `json:"password_salt"`
		PasswordHashAlgorithm       string          `json:"password_hash_algorithm"`
		PasswordHashOperationsLimit uint            `json:"password_hash_operations_limit"`
		PasswordHashMemoryLimit     uint64          `json:"password_hash_memory_limit"`
		PublicKey                   encodable.Bytes `json:"public_key"`
		WrappedSecretKey            encodable.Bytes `json:"wrapped_secret_key"`
		WrappedSecretKeyNonce       encodable.Bytes `json:"wrapped_secret_key_nonce"`
		WrappedSymmetricKey         encodable.Bytes `json:"wrapped_symmetric_key"`
		WrappedSymmetricKeyNonce    encodable.Bytes `json:"wrapped_symmetric_key_nonce"`
	}{
		Username:                    tu.username,
		PasswordSalt:                tu.passwordSalt,
		PasswordHashAlgorithm:       tu.passwordHashAlg.Name,
		PasswordHashOperationsLimit: tu.passwordHashOpsLimit,
		PasswordHashMemoryLimit:     tu.passwordHashMemLimit,
		PublicKey:                   tu.keyPair.Public,
		WrappedSecretKey:            tu.wrappedSecretKeyCipherText,
		WrappedSecretKeyNonce:       tu.wrappedSecretKeyNonce,
		WrappedSymmetricKey:         tu.wrappedSymmetricKeyCipherText,
		WrappedSymmetricKeyNonce:    tu.wrappedSymmetricKeyNonce,
	}

	buf, _ := json.Marshal(body)
	return bytes.NewReader(buf)
}

func createUserOnServer(t *testing.T) testUser {
	user := newUser(t)
	req, _ := http.NewRequest(http.MethodPost, apiRoot+"/alpha/users", user.userReader())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	respBody := struct {
		ID       encodable.Bytes `json:"id"`
		Username string          `json:"username"`
	}{}

	if err = json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatal(err)
	}

	if len(respBody.ID) != 16 {
		t.Fatalf("user id length is wrong - found %d", len(respBody.ID))
	}

	user.publicID = respBody.ID

	return user
}

func newUser(t *testing.T) testUser {
	u := testUser{
		username: base62.Rand(7),
		password: base62.Rand(8),
	}
	var err error
	u.keyPair, err = sodium.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	u.passwordSalt = make([]byte, sodium.PasswordStretchingSaltSize)
	if err = sodium.Random(u.passwordSalt); err != nil {
		t.Fatal(err)
	}
	u.passwordHashAlg = sodium.Argon2id13
	u.passwordHashOpsLimit = sodium.Argon2id13.OpsLimitInteractive
	u.passwordHashMemLimit = sodium.Argon2id13.MemLimitInteractive
	u.passwordHash, err = sodium.StretchPassword(sodium.SymmetricKeySize,
		u.password,
		u.passwordSalt,
		u.passwordHashAlg,
		u.passwordHashOpsLimit,
		u.passwordHashMemLimit)
	if err != nil {
		t.Fatal(err)
	}

	u.symmetricKey = make([]byte, sodium.SymmetricKeySize)
	if err = sodium.Random(u.symmetricKey); err != nil {
		t.Fatal(err)
	}
	u.wrappedSymmetricKeyCipherText, u.wrappedSymmetricKeyNonce, err = sodium.SymmetricKeyEncrypt(u.symmetricKey, u.passwordHash)
	if err != nil {
		t.Fatal(err)
	}

	u.wrappedSecretKeyCipherText, u.wrappedSecretKeyNonce, err = sodium.SymmetricKeyEncrypt(u.keyPair.Secret, u.passwordHash)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func TestCreateUser(t *testing.T) {
	createUserOnServer(t)
}

func TestSearchUsers(t *testing.T) {
	user := createUserOnServer(t)
	accessToken := login(user, t)

	// search for ourself
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/alpha/users?username="+user.username, nil)
	req.Header.Add("X-Oscar-Access-Token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	searchResp := struct {
		ID        encodable.Bytes `json:"id"`
		PublicKey encodable.Bytes `json:"public_key"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		t.Fatal(err)
	}
	// make sure the id and key match
	if !bytes.Equal(searchResp.ID, user.publicID) {
		t.Fatal("id mismatch")
	}
	if !bytes.Equal(searchResp.PublicKey, user.keyPair.Public) {
		t.Fatal("public key mismatch")
	}

	// search for a non-existent user
	req, _ = http.NewRequest(http.MethodGet, apiRoot+"/alpha/users?username=gob", nil)
	req.Header.Add("X-Oscar-Access-Token", accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Status should have been 'not found'. Got %d", resp.StatusCode)
	}
}

func TestUserDataBackups(t *testing.T) {
	user := createUserOnServer(t)
	token := login(user, t)

	// check for a database backup for this new user
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/alpha/users/me/backup", nil)
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// we should get a 404, because there is no backup yet
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// now put some data there
	data := []byte("This is a database backup. It's encrypted data.")
	req, _ = http.NewRequest(http.MethodPut, apiRoot+"/alpha/users/me/backup", bytes.NewReader(data))
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// now retrieve the backup
	req, _ = http.NewRequest(http.MethodGet, apiRoot+"/alpha/users/me/backup", nil)
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}
	dledData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dledData, data) {
		t.Fatal("Backup data didn't match")
	}
}

func TestGetUserPublicKey(t *testing.T) {
	// attempt retrieval of a key from a non-existent user
	resp, err := http.Get(apiRoot + "/alpha/users/deadbeefbeefdead/public-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// create a user and verify their key after retrieval
	user := createUserOnServer(t)
	resp, err = http.Get(apiRoot + "/alpha/users/" + hex.EncodeToString(user.publicID) + "/public-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	obj := struct {
		PublicKey encodable.Bytes `json:"public_key"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(obj.PublicKey, user.keyPair.Public) {
		t.Fatalf("Retrieved public key does not match: %s != %s",
			hex.EncodeToString(obj.PublicKey),
			hex.EncodeToString(user.keyPair.Public))
	}
}

func TestGetUserInfo(t *testing.T) {
	user := createUserOnServer(t)
	token := login(user, t)

	// attempt retrieval of a non-existent user
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/users/deadbeefbeefdead", nil)
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// retrieve our own info, then verify that it matches
	req, _ = http.NewRequest(http.MethodGet, apiRoot+"/alpha/users/"+hex.EncodeToString(user.publicID), nil)
	req.Header.Add("X-Oscar-Access-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	obj := struct {
		Username  string          `json:"username"`
		PublicKey encodable.Bytes `json:"public_key"`
	}{}
	if err = json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		t.Fatal(err)
	}

	// verify that the data matches
	if obj.Username != strings.ToLower(user.username) {
		t.Fatalf("username does not match: %s != %s", obj.Username, strings.ToLower(user.username))
	}
	if !bytes.Equal(obj.PublicKey, user.keyPair.Public) {
		t.Fatalf("public key does not match: %s != %s",
			hex.EncodeToString(obj.PublicKey),
			hex.EncodeToString(user.keyPair.Public))
	}
}
