package sodium

/*
#cgo LDFLAGS: -lsodium

#include <sodium.h>
#include <stdlib.h>
*/
import "C"
import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

func init() {
	C.sodium_init()
}

// KeyPair holds a public and secret key that can be used for asymmetric encryption
type KeyPair struct {
	Public []byte
	Secret []byte
}

// Algorithm is a descriptor of an algorithm for password stretching
type Algorithm struct {
	Name                string
	ID                  int
	SaltLength          uint
	OpsLimitInteractive uint
	OpsLimitModerate    uint
	OpsLimitSensitive   uint

	MemLimitInteractive uint64
	MemLimitModerate    uint64
	MemLimitSensitive   uint64
}

// Argon2i13 is the older password stretching algorithm
var Argon2i13 = Algorithm{
	Name:                "argon2i13",
	ID:                  C.crypto_pwhash_ALG_ARGON2I13,
	SaltLength:          16,
	OpsLimitInteractive: C.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
	OpsLimitModerate:    C.crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
	OpsLimitSensitive:   C.crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE,
	MemLimitInteractive: C.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
	MemLimitModerate:    C.crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
	MemLimitSensitive:   C.crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE}

// Argon2id13 is the newer/better password stretching algorithm
var Argon2id13 = Algorithm{
	Name:                "argon2id13",
	ID:                  C.crypto_pwhash_ALG_ARGON2ID13,
	SaltLength:          16,
	OpsLimitInteractive: C.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
	OpsLimitModerate:    C.crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
	OpsLimitSensitive:   C.crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
	MemLimitInteractive: C.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
	MemLimitModerate:    C.crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
	MemLimitSensitive:   C.crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE}

// SymmetricKeySize is the length in bytes of a key for symmetric crypto operations
const SymmetricKeySize = C.crypto_secretbox_KEYBYTES

// SymmetricNonceSize is the length of the nonce used in a symmetric crypto operation
const SymmetricNonceSize = C.crypto_secretbox_NONCEBYTES

// AsymmetricNonceSize is the size in bytes of a nonce used in public-secret key crypto operation
const AsymmetricNonceSize = C.crypto_box_NONCEBYTES

// PublicKeySize is the size in bytes of a public key in a KeyPair
const PublicKeySize = C.crypto_box_PUBLICKEYBYTES

// SecretKeySize is the size in bytes of a secret key in a KeyPair
const SecretKeySize = C.crypto_box_SECRETKEYBYTES

const boxNonceSize = C.crypto_box_NONCEBYTES
const boxMACSize = C.crypto_box_MACBYTES
const secretBoxMACSize = C.crypto_secretbox_MACBYTES
const secretBoxNonceSize = C.crypto_secretbox_NONCEBYTES
const secretBoxKeySize = C.crypto_secretbox_KEYBYTES

func (kp KeyPair) String() string {
	return fmt.Sprintf("public: %s\nsecret: %s",
		hex.EncodeToString(kp.Public),
		hex.EncodeToString(kp.Secret))
}

// NewKeyPair creates an asymmetric pair of keys
func NewKeyPair() (KeyPair, error) {
	kp := KeyPair{}
	kp.Public = make([]byte, PublicKeySize)
	kp.Secret = make([]byte, SecretKeySize)
	result := C.crypto_box_keypair((*C.uchar)(&kp.Public[0]), (*C.uchar)(&kp.Secret[0]))
	if result != 0 {
		return kp, fmt.Errorf("unknown error generating key pair (%d)", result)
	}

	return kp, nil
}

// PublicKeyDecrypt decrypts a message using asymmetric cryptography
func PublicKeyDecrypt(cipherText, nonce, senderPublicKey, receiverSecretKey []byte) ([]byte, bool) {
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

// PublicKeyEncrypt encrypts a message using asymmetric cryptography
func PublicKeyEncrypt(msg, receiverPubKey, senderSecretKey []byte) (cipherText, nonce []byte, err error) {
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

// Random overwrites b with random data.
func Random(b []byte) error {
	_, err := crand.Read(b)
	return err
}

// StretchPassword stretches a password to keySize bytes
func StretchPassword(keySize int, pw string, salt []byte, alg Algorithm, opsLimit uint, memLimit uint64) ([]byte, error) {
	key := make([]byte, keySize)
	pwc := C.CString(pw)
	defer C.free(unsafe.Pointer(pwc))
	result := C.crypto_pwhash(
		(*C.uchar)(&key[0]),
		C.ulonglong(keySize),
		pwc,
		C.ulonglong(len(pw)),
		(*C.uchar)(&salt[0]),
		C.ulonglong(opsLimit),
		C.ulong(memLimit),
		C.int(alg.ID))
	if result != 0 {
		return nil, errors.New("out of memory")
	}

	return key, nil
}

// SymmetricKeyEncrypt encrypts a message using symmetric cryptography
func SymmetricKeyEncrypt(msg, key []byte) (cipherText, nonce []byte, err error) {
	if len(key) != SymmetricKeySize {
		return nil, nil, errors.New("Key should be 'SymmetricKeySize' bytes long")
	}
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

	return
}

// SymmetricKeyDecrypt decrypts a message using symmetric cryptography
func SymmetricKeyDecrypt(cipherText, nonce, key []byte) ([]byte, bool) {
	if len(key) != SymmetricKeySize {
		return nil, false
	}
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
