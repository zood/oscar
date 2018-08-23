package sodium

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNewKeyPair(t *testing.T) {
	a, err := NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if a.Public == nil || len(a.Public) != PublicKeySize {
		t.Fatal("Invalid public key")
	}

	if len(a.Secret) != SecretKeySize {
		t.Fatal("Invalid secret key")
	}

	if a.String() == "" {
		t.Fatal("String() should produce some output")
	}
}

func TestPasswordStretching(t *testing.T) {
	password := "bananastand"
	salt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	key, err := StretchPassword(16, password, salt, Argon2i13, Argon2i13.OpsLimitInteractive, Argon2i13.MemLimitInteractive)
	if err != nil {
		t.Fatal(err)
	}

	argon2iKey := "19ed042d6c1db20ce284ee35e831a891"
	if hex.EncodeToString(key) != argon2iKey {
		t.Fatalf("argon2i stretching mismatch: %s != %s", hex.EncodeToString(key), argon2iKey)
	}

	key, err = StretchPassword(16, password, salt, Argon2id13, Argon2id13.OpsLimitInteractive, Argon2id13.MemLimitInteractive)
	if err != nil {
		t.Fatal(err)
	}

	argon2idKey := "eba77f4c8d3e8833d1d0cf1a42b2a1d2"
	if hex.EncodeToString(key) != argon2idKey {
		t.Fatalf("argon2id stretching mismatch: %s != %s", hex.EncodeToString(key), argon2idKey)
	}
}

func TestPublicKeyCrypto(t *testing.T) {
	alice, _ := NewKeyPair()
	bob, _ := NewKeyPair()

	msg := []byte("Hello, world!")

	ct, nonce, err := PublicKeyEncrypt(msg, bob.Public, alice.Secret)
	if err != nil {
		t.Fatal(err)
	}

	decryptedMsg, ok := PublicKeyDecrypt(ct, nonce, alice.Public, bob.Secret)
	if !ok {
		t.Fatal("decryption failed")
	}

	if !bytes.Equal(msg, decryptedMsg) {
		t.Fatal("Decrypted message didn't match original")
	}
}

func TestRandom(t *testing.T) {
	buf := make([]byte, 32)
	err := Random(buf)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(buf, make([]byte, 32)) {
		t.Fatal("Slice does not contain random data")
	}
}

func TestSymmetricCrypto(t *testing.T) {
	key := make([]byte, SymmetricKeySize)
	Random(key)

	msg := []byte("Hello, world!")
	ct, nonce, err := SymmetricKeyEncrypt(msg, key)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, ok := SymmetricKeyDecrypt(ct, nonce, key)
	if !ok {
		t.Fatal("Symmetric decryption failed")
	}

	if !bytes.Equal(msg, decrypted) {
		t.Fatal("Decrypted output didn't match input")
	}

	// test failure cases
	_, _, err = SymmetricKeyEncrypt(msg, nil)
	if err == nil {
		t.Fatal("There should have been an error when passing a nil key")
	}

	_, ok = SymmetricKeyDecrypt(ct, nonce, nil)
	if ok {
		t.Fatal("Decryption should have failed")
	}
	_, ok = SymmetricKeyDecrypt(ct[:len(ct)-1], nonce, key)
	if ok {
		t.Fatal("Decryption should have failed")
	}
}
