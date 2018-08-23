package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"zood.xyz/oscar/base62"
	"zood.xyz/oscar/encodable"
	"zood.xyz/oscar/sodium"
)

const apiRoot = "http://localhost:4046"

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

func TestServerInfo(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/server-info", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	obj := struct {
		BuildTime string `json:"build_time"`
		SysKb     int    `json:"sys_kb"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateUser(t *testing.T) {
	user := newUser(t)
	req, _ := http.NewRequest(http.MethodPost, apiRoot+"/alpha/users", user.userReader())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrec status code: %d", resp.StatusCode)
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
}
