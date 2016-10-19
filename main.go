package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

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
	r.Handle("/users", newRESTFunc(searchUsersHandler)).Methods("GET")
	r.Handle("/users", newRESTFunc(createUserHandler)).Methods("POST")
	r.Handle("/users/{public_id}", newRESTFunc(getUserInfoHandler)).Methods("GET")
	r.Handle("/users/{public_id}/messages", newRESTFunc(sendMessageToUserHandler)).Methods("POST")
	r.Handle("/users/{public_id}/public-key", newRESTFunc(getUserPublicKeyHandler)).Methods("GET")

	r.Handle("/messages", newRESTFunc(getMessagesHandler)).Methods("GET")
	r.Handle("/messages/{msg_id}/processed", newRESTFunc(editMessageHandler)).Methods("PUT")

	r.Handle("/drop-boxes/{box_id}", newRESTFunc(getDropBoxPackageHandler)).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", newRESTFunc(dropPackageHandler)).Methods("POST")

	r.Handle("/sessions/{username}/challenge", newRESTFunc(createAuthChallengeHandler)).Methods("POST")
	r.Handle("/sessions/{username}/challenge-response", newRESTFunc(authChallengeResponseHandler)).Methods("POST")
}

func playground() {
	key := make([]byte, secretBoxKeySize)
	crand.Read(key)
	log.Printf("key: %s", hex.EncodeToString(key))
	/*
		key := make([]byte, secretBoxKeySize)
		crand.Read(key)
		msg := `{"uid":1, "ct":1473287177}`
		cipherText, nonce, err := symmetricKeyEncrypt([]byte(msg), key)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ct size: %d, nonce size: %d", len(cipherText), len(nonce))
		tokenMaterial := append(cipherText, nonce...)
		token := hex.EncodeToString(tokenMaterial)
		log.Printf("token: %s", token)

		decodedToken, err := hex.DecodeString(token)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("decoded len: %d", len(decodedToken))
		nonceStart := len(decodedToken) - secretBoxNonceSize
		log.Printf("nonceStart: %d", nonceStart)
		decodedNonce := decodedToken[nonceStart:]
		decodedCipherText := decodedToken[0:nonceStart]
		origMsg, ok := symmetricKeyDecrypt(decodedCipherText, decodedNonce, key)
		if !ok {
			log.Fatal("unable to decrypt msg")
		}
		log.Printf("orig msg: %s", origMsg)
	*/
}
