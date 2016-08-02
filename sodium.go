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
		C.crypto_pwhash_OPSLIMIT_INTERACTIVE,
		C.crypto_pwhash_MEMLIMIT_INTERACTIVE,
		C.crypto_pwhash_ALG_DEFAULT)
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

func publicKeyEncryptMessage(msg, receiverPubKey, senderSecretKey []byte) (cipherText, nonce []byte, err error) {
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

func publicKeyDecryptMessage(cipherText, nonce, senderPublicKey, receiverSecretKey []byte) ([]byte, bool) {
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

func secretBoxMessage(msg, key []byte) (cipherText, nonce []byte, err error) {
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

func secretBoxOpenMessage(cipherText, nonce, key []byte) ([]byte, bool) {
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

/*
func sealMessage(msg, additionalData, nonce, key []byte) ([]byte, error) {
	cipherText := make([]byte, len(msg)+chacha20poly1305IETFABytes)
	result := C.crypto_aead_chacha20poly1305_ietf_encrypt(
		(*C.uchar)(&cipherText[0]), C.ulonglong(len(cipherText)),
		(*C.uchar)(&msg[0]), C.ulonglong(len(msg)),
		(*C.uchar)(&additionalData[0]), C.ulonglong(len(additionalData)),
		nil,
		(*C.uchar)(&nonce[0]),
		(*C.uchar)(&key[0]))
	return nil, nil
}
*/
