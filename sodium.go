package main

/*
#cgo LDFLAGS: -lsodium

#include <sodium.h>
*/
import "C"
import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

func init() {
	C.sodium_init()
}

type keyPair struct {
	public []byte
	secret []byte
}

const boxNonceSize = C.crypto_box_NONCEBYTES
const publicKeySize = C.crypto_box_PUBLICKEYBYTES
const secretKeySize = C.crypto_box_SECRETKEYBYTES
const boxMACSize = C.crypto_box_MACBYTES
const secretBoxMACSize = C.crypto_secretbox_MACBYTES
const secretBoxNonceSize = C.crypto_secretbox_NONCEBYTES
const secretBoxKeySize = C.crypto_secretbox_KEYBYTES
const argon2iOpsLimitInteractive = C.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
const argon2iMemLimitInteractive = C.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE

func (kp keyPair) String() string {
	return fmt.Sprintf("public: %s\nsecret: %s",
		hex.EncodeToString(kp.public),
		hex.EncodeToString(kp.secret))
}

func keyFromPassword(keySize int, pw string, salt []byte) ([]byte, error) {
	key := make([]byte, keySize)
	pwc := C.CString(pw)
	result := C.crypto_pwhash(
		(*C.uchar)(&key[0]),
		C.ulonglong(keySize),
		pwc,
		C.ulonglong(len(pw)),
		(*C.uchar)(&salt[0]),
		argon2iOpsLimitInteractive,
		argon2iMemLimitInteractive,
		C.crypto_pwhash_ALG_ARGON2I13)
	if result != 0 {
		return nil, errors.New("out of memory")
	}

	return key, nil
}

func generateKeyPair() (keyPair, error) {
	kp := keyPair{}
	kp.public = make([]byte, publicKeySize)
	kp.secret = make([]byte, secretKeySize)
	result := C.crypto_box_keypair((*C.uchar)(&kp.public[0]), (*C.uchar)(&kp.secret[0]))
	if result != 0 {
		return kp, fmt.Errorf("unknown error generating key pair (%d)", result)
	}

	return kp, nil
}

func publicKeyEncrypt(msg, receiverPubKey, senderSecretKey []byte) (cipherText, nonce []byte, err error) {
	cipherText = make([]byte, boxMACSize+len(msg))
	nonce = make([]byte, boxNonceSize)
	crand.Read(nonce)
	result := C.crypto_box_easy(
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&msg[0]),
		C.ulonglong(len(msg)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&receiverPubKey[0]),
		(*C.uchar)(&senderSecretKey[0]))
	if result != 0 {
		return nil, nil, fmt.Errorf("unknown error boxing message (%d)", result)
	}

	return
}

func publicKeyDecrypt(cipherText, nonce, senderPublicKey, receiverSecretKey []byte) ([]byte, bool) {
	msg := make([]byte, len(cipherText)-boxMACSize)
	result := C.crypto_box_open_easy(
		(*C.uchar)(&msg[0]),
		(*C.uchar)(&cipherText[0]),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&senderPublicKey[0]),
		(*C.uchar)(&receiverSecretKey[0]))
	if result != 0 {
		// message has been forged
		return nil, false
	}

	return msg, true
}

/*
func publicKeyEncryptUnauthenticated(msg, publicKey []byte) (cipherText []byte, err error) {
	cipherText = make([]byte, C.crypto_box_SEALBYTES+len(msg))
	result := C.crypto_box_seal(
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&msg[0]),
		C.ulonglong(len(msg)),
		(*C.uchar)(&publicKey[0]))
	if result != 0 {
		return nil, fmt.Errorf("unknown error in crypto_box_seal (%d)", result)
	}

	return cipherText, nil
}
*/

// func publicKeyDecryptUnauthenticated(cipherText)

func symmetricKeyEncrypt(msg, key []byte) (cipherText, nonce []byte, err error) {
	cipherText = make([]byte, len(msg)+secretBoxMACSize)
	nonce = make([]byte, secretBoxNonceSize)
	crand.Read(nonce)
	result := C.crypto_secretbox_easy(
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&msg[0]),
		C.ulonglong(len(msg)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]))
	if result != 0 {
		return nil, nil, fmt.Errorf("unknown error secret boxing message (%d)", result)
	}

	// return cipherText, nil
	return
}

func symmetricKeyDecrypt(cipherText, nonce, key []byte) ([]byte, bool) {
	msg := make([]byte, len(cipherText)-secretBoxMACSize)
	result := C.crypto_secretbox_open_easy(
		(*C.uchar)(&msg[0]),
		(*C.uchar)(&cipherText[0]),
		C.ulonglong(len(cipherText)),
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]))
	if result != 0 {
		return nil, false
	}
	return msg, true
}

func hashData(data, key []byte) ([]byte, bool) {
	hash := make([]byte, C.crypto_generichash_BYTES)
	result := C.crypto_generichash(
		(*C.uchar)(&hash[0]),
		C.crypto_generichash_BYTES,
		(*C.uchar)(&data[0]),
		C.ulonglong(len(data)),
		(*C.uchar)(&key[0]),
		C.size_t(len(key)))
	if result != 0 {
		return nil, false
	}

	return hash, true
}
