package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gorilla/mux"
)

// Debug contains whether the server is running in debug mode
var Debug = false

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	port := flag.Int("port", 80, "Listening port for server")
	debug := flag.Bool("debug", false, "Enables additional log output")
	sqlDSN := flag.String(
		"sqldsn",
		"",
		"DSN to SQL server e.g. username:password@protocol(address)/dbname?param=value")
	kvDBPath := flag.String("kvdb", "", "Path to key-value database file")
	flag.Parse()
	Debug = *debug

	err := initDB(*sqlDSN)
	if err != nil {
		log.Fatalf("Error initializing SQL db: %v", err)
	}

	err = initKVDB(*kvDBPath)
	if err != nil {
		log.Fatalf("Error initializing key-value db: %v", err)
	}

	r := mux.NewRouter()
	alphaRouter := r.PathPrefix("/alpha").Subrouter()
	installEndPoints(alphaRouter)

	// playground()

	hostAddress := fmt.Sprintf(":%d", *port)
	server := http.Server{
		Addr:         hostAddress,
		Handler:      r,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	log.Printf("Starting server on port %d", *port)
	server.ListenAndServe()
}

func installEndPoints(r *mux.Router) {
	// r.Handle("/users", NewRESTFunc(CreateUserHandler)).Methods("GET")
	r.Handle("/users", NewRESTFunc(CreateUserHandler)).Methods("POST")

	r.Handle("/users/{public_id}/messages", NewRESTFunc(GetUserMessagesHandler)).Methods("GET")

	// r.Handle("/sessions/challenge", NewRESTFunc(GetAuthenticationChallengeHandler)).Methods("GET")
}

func playground() {
	kvdb().Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(userIDsBucketName)
		bucket.Put([]byte("gabble gabble"), []byte("goo goo"))
		return nil
	})

	kvdb().View(func(tx *bolt.Tx) error {
		val := tx.Bucket(userIDsBucketName).Get([]byte("gabble sgabble"))
		log.Printf("gabble value: %s", val)
		return nil
	})

	// salt, err := hex.DecodeString()
	// if err != nil {
	// 	log.Fatalf("salt err: %v", err);
	// }

	/*
		key, err := hex.DecodeString("574c1aa36561e5e748a659f0ba8d4e2fb398512cb07d907579b0a7b1fbf2e50d")
		if err != nil {
			log.Fatalf("key err: %v", err)
		}
		cipherText, err := hex.DecodeString("c3f48480985a2b6f10b7703568807336a2b0a67eaa218f74c28b405be4c94f2b")
		if err != nil {
			log.Fatalf("cipherText err: %v", err)
		}
		nonce, err := hex.DecodeString("28861eac5b6eb77e3fa768ef5beae5663d88dc8663c32e2b")
		if err != nil {
			log.Fatalf("nonce: %v", err)
		}

		msg, ok := symmetricKeyDecrypt(cipherText, nonce, key)
		if !ok {
			log.Printf("failed to open message")
			return
		}
		log.Printf("msg: %v", string(msg))
	*/

	// key stretching the password
	/*
		salt := make([]byte, secretBoxKeySize)
		crand.Read(salt)
		key, err := keyFromPassword(secretBoxKeySize, "foo", salt)
		if err != nil {
			log.Fatalf("error hashing: %v", err)
		}
		log.Printf("key: %v", key)

		msg := "my secret settings"
		cipherText, nonce, err := secretBoxMessage([]byte(msg), key)
		if err != nil {
			log.Fatalf("unable to secret box message: %v", err)
		}
		log.Printf("cipherText: %s\nnonce: %s", hex.EncodeToString(cipherText), hex.EncodeToString(nonce))

		outMsg, ok := secretBoxOpenMessage(cipherText, nonce, key)
		if !ok {
			log.Fatalf("message was forged!")
		}
		log.Printf("out message: %s", string(outMsg))
	*/

	// public key encryption
	/*
		aliceKeys, err := generateKeyPair()
		if err != nil {
			log.Printf("couldn't create alice's keys: %v", err)
		}
		bobKeys, err := generateKeyPair()
		if err != nil {
			log.Printf("Couldn't create bob's keys: %v", err)
		}
		log.Printf("Alice Keys: %v", aliceKeys)
		log.Printf("Bob's Keys: %v", bobKeys)

		msg := "something hidden"
		cipherText, nonce, err := publicKeyEncryptMessage([]byte(msg), bobKeys.public, aliceKeys.secret)
		if err != nil {
			log.Printf("unable to encrypt message")
		}
		log.Printf("cipher text: %s", hex.EncodeToString(cipherText))
		log.Printf("nonce: %s", hex.EncodeToString(nonce))

		outMsg, ok := publicKeyDecryptMessage(cipherText, nonce, aliceKeys.public, bobKeys.secret)
		if !ok {
			log.Printf("decrypted message not valid")
		}
		log.Printf("out msg: %s", string(outMsg))
	*/

}
