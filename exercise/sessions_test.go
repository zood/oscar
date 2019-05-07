package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"zood.dev/oscar/encodable"
	"zood.dev/oscar/sodium"
)

type authenticationChallenge struct {
	User struct {
		PublicKey                   encodable.Bytes `json:"public_key"`
		WrappedSecretKey            encodable.Bytes `json:"wrapped_secret_key"`
		WrappedSecretKeyNonce       encodable.Bytes `json:"wrapped_secret_key_nonce"`
		PasswordSalt                encodable.Bytes `json:"password_salt"`
		PasswordHashAlgorithm       string          `json:"password_hash_algorithm"`
		PasswordHashOperationsLimit uint            `json:"password_hash_operations_limit"`
		PasswordHashMemoryLimit     uint64          `json:"password_hash_memory_limit"`
	} `json:"user"`
	Challenge    encodable.Bytes `json:"challenge"`
	CreationDate encodable.Bytes `json:"creation_date"`
}

type encryptedData struct {
	CipherText encodable.Bytes `json:"cipher_text"`
	Nonce      encodable.Bytes `json:"nonce"`
}

type finishedAuthenticationChallenge struct {
	Challenge    encryptedData `json:"challenge"`
	CreationDate encryptedData `json:"creation_date"`
}

type loginResponse struct {
	ID                       encodable.Bytes `json:"id"`
	AccessToken              string          `json:"access_token"`
	WrappedSymmetricKey      encodable.Bytes `json:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce encodable.Bytes `json:"wrapped_symmetric_key_nonce"`
}

// upon successful login, returns an access token
func login(user testUser, t *testing.T) string {
	// create an authentication challenge
	req, _ := http.NewRequest(http.MethodPost, apiRoot+"/alpha/sessions/"+user.username+"/challenge", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	challenge := authenticationChallenge{}
	if err = json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}

	// make sure the returned user parts match our user object
	if !bytes.Equal(challenge.User.PublicKey, user.keyPair.Public) {
		t.Fatalf("user public key doesn't match: %s != %s",
			hex.EncodeToString(challenge.User.PublicKey),
			hex.EncodeToString(user.keyPair.Public))
	}
	if !bytes.Equal(challenge.User.WrappedSecretKey, user.wrappedSecretKeyCipherText) {
		t.Fatalf("wrapped secret key cipher text doesn't match: %s != %s",
			hex.EncodeToString(challenge.User.WrappedSecretKey),
			hex.EncodeToString(user.wrappedSecretKeyCipherText))
	}
	if !bytes.Equal(challenge.User.WrappedSecretKeyNonce, user.wrappedSecretKeyNonce) {
		t.Fatalf("wrapped secret key nonce doesn't match: %s != %s",
			hex.EncodeToString(challenge.User.WrappedSecretKeyNonce),
			hex.EncodeToString(user.wrappedSecretKeyNonce))
	}
	if !bytes.Equal(challenge.User.PasswordSalt, user.passwordSalt) {
		t.Fatalf("password salt doesn't match: %s != %s",
			hex.EncodeToString(challenge.User.PasswordSalt),
			hex.EncodeToString(user.passwordSalt))
	}
	if challenge.User.PasswordHashAlgorithm != user.passwordHashAlg.Name {
		t.Fatalf("hash alg mismatch: %s != %s", challenge.User.PasswordHashAlgorithm, user.passwordHashAlg.Name)
	}
	if challenge.User.PasswordHashOperationsLimit != user.passwordHashOpsLimit {
		t.Fatalf("ops limit mismatch: %d != %d", challenge.User.PasswordHashOperationsLimit, user.passwordHashOpsLimit)
	}
	if challenge.User.PasswordHashMemoryLimit != user.passwordHashMemLimit {
		t.Fatalf("mem limit mismatch: %d != %d", challenge.User.PasswordHashMemoryLimit, user.passwordHashMemLimit)
	}

	// grab the server's public key
	resp, err = http.DefaultClient.Get(apiRoot + "/alpha/public-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	pubKeyResp := struct {
		PublicKey encodable.Bytes `json:"public_key"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&pubKeyResp)
	if err != nil {
		t.Fatal(err)
	}

	// make sure this is a valid public key
	if len(pubKeyResp.PublicKey) != sodium.PublicKeySize {
		t.Fatalf("Invalid public key size. Should be %d. Found %d.", sodium.PublicKeySize, len(pubKeyResp.PublicKey))
	}
	// make sure it's not just a bunch of zeros
	if bytes.Equal(pubKeyResp.PublicKey, make([]byte, sodium.PublicKeySize)) {
		t.Fatalf("Server's public key is just a bunch of zeros")
	}

	ct, nonce, err := sodium.PublicKeyEncrypt(challenge.Challenge, pubKeyResp.PublicKey, user.keyPair.Secret)
	if err != nil {
		t.Fatal(err)
	}

	finished := finishedAuthenticationChallenge{}
	finished.Challenge = encryptedData{
		CipherText: ct,
		Nonce:      nonce,
	}

	ct, nonce, err = sodium.PublicKeyEncrypt(challenge.CreationDate, pubKeyResp.PublicKey, user.keyPair.Secret)
	if err != nil {
		t.Fatal(err)
	}

	finished.CreationDate = encryptedData{
		CipherText: ct,
		Nonce:      nonce,
	}

	finishedJSON, err := json.Marshal(finished)
	if err != nil {
		t.Fatal(err)
	}

	req, _ = http.NewRequest(http.MethodPost,
		apiRoot+"/alpha/sessions/"+user.username+"/challenge-response",
		bytes.NewReader(finishedJSON))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	loginResp := loginResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatal(err)
	}

	// let's validate the returned fields
	if !bytes.Equal(loginResp.ID, user.publicID) {
		t.Fatal("Public id mismatch")
	}
	if !bytes.Equal(loginResp.WrappedSymmetricKey, user.wrappedSymmetricKeyCipherText) {
		t.Fatal("symmetric key cipher text mismatch")
	}
	if !bytes.Equal(loginResp.WrappedSymmetricKeyNonce, user.wrappedSymmetricKeyNonce) {
		t.Fatal("symmetric key nonce mismatch")
	}

	return loginResp.AccessToken
}

func TestLogin(t *testing.T) {
	user := createUserOnServer(t)
	accessToken := login(user, t)

	// make sure the access token isn't empty
	if accessToken == "" {
		t.Fatal("Did not receive an access token")
	}
}
