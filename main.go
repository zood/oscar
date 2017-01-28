package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/gorilla/mux"
)

// Debug contains whether the server is running in debug mode
var Debug = false

var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
	// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	debug := flag.Bool("debug", false, "Enables additional log output")
	configPath := flag.String("config", "", "Path to config file")
	flag.Parse()
	Debug = *debug

	port, tlsEnabled, err := applyConfigFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	alphaRouter := r.PathPrefix("/alpha").Subrouter()
	installEndPoints(alphaRouter)

	// playground()

	hostAddress := fmt.Sprintf(":%d", port)
	server := http.Server{
		Addr:         hostAddress,
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		// IdleTimeout:  120 * time.Second,	// Go 1.8
	}

	log.Printf("Starting server on port %d", port)
	if tlsEnabled {
		tlsConfig := &tls.Config{}
		tlsConfig.CipherSuites = defaultCiphers
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.PreferServerCipherSuites = true
		tlsConfig.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			//tls.X25519, // Go 1.8 only
		}
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("api.pijun.io"),
			Cache:      autocert.DirCache("./"),
		}
		tlsConfig.GetCertificate = m.GetCertificate
		server.TLSConfig = tlsConfig
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func installEndPoints(r *mux.Router) {
	r.Handle("/users", logHandler(sessionHandler(searchUsersHandler))).Methods("GET")
	r.Handle("/users", logHandler(createUserHandler)).Methods("POST")
	r.Handle("/users/me/fcm-tokens", logHandler(sessionHandler(addFCMTokenHandler))).Methods("POST")
	r.Handle("/users/me/fcm-tokens/{token}", logHandler(sessionHandler(deleteFCMTokenHandler))).Methods("DELETE")
	r.Handle("/users/me/backup", logHandler(sessionHandler(retrieveBackupHandler))).Methods("GET")
	r.Handle("/users/me/backup", logHandler(sessionHandler(saveBackupHandler))).Methods("PUT")
	r.Handle("/users/{public_id}", logHandler(sessionHandler(getUserInfoHandler))).Methods("GET")
	r.Handle("/users/{public_id}/messages", logHandler(sessionHandler(sendMessageToUserHandler))).Methods("POST")
	r.Handle("/users/{public_id}/public-key", logHandler(corsHandler(getUserPublicKeyHandler))).Methods("GET")

	r.Handle("/messages", logHandler(sessionHandler(getMessagesHandler))).Methods("GET")
	r.Handle("/messages/{message_id:[0-9]+}", logHandler(sessionHandler(deleteMessageHandler))).Methods("DELETE")

	// this has to come first, so it has a chance to match before the box_id urls
	r.Handle("/drop-boxes/watch", logHandler(createPackageWatcherHandler)).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(pickUpPackageHandler))).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(dropPackageHandler))).Methods("PUT")

	r.Handle("/public-key", logHandler(getServerPublicKeyHandler)).Methods("GET")

	r.Handle("/sessions/{username}/challenge", logHandler(createAuthChallengeHandler)).Methods("POST")
	r.Handle("/sessions/{username}/challenge-response", logHandler(authChallengeResponseHandler)).Methods("POST")

	r.Handle("/goroutine-stacks", logHandler(goroutineStacksHandler)).Methods("GET")
	r.Handle("/test", logHandler(testHandler)).Methods("GET")
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	// pushMessageToUser(22, 16)
	sendFirebaseMessage(16, nil, false)
}

func playground() {
	/*
		{
			"n": "arash",
			"iat": // unix epoch time
			"eat": // base64(ec256(iat))
		}
	*/

	serverSecretKey, _ := hex.DecodeString("e1daa9c01ac0684cd137a76b94984872c6e2c82ac50a1eb55919656758fdc022")
	// log.Printf("server secret key: %s", hex.EncodeToString(serverSecretKey))

	now := time.Unix(1485481237, 0)
	// log.Printf("unix time: %v", now.Unix())

	serverKeyPair := keyPair{}
	serverKeyPair.public, _ = hex.DecodeString("e899018b82d5d7279591a17bfcf83654ab9b53f233eb524ff5d3d9aabeb94c7d")
	serverKeyPair.secret, _ = hex.DecodeString("2c66b081340f716737e7a5aaadbf27cf1899bf5b135f3c9c9d42e452178b1340")
	// log.Printf("server keypair: %v", serverKeyPair)

	clientKeyPair := keyPair{}
	clientKeyPair.public, _ = hex.DecodeString("bc763beacf24618791e7585ecefce49374a7f58687a2d7fa893e99e8d007854b")
	clientKeyPair.secret, _ = hex.DecodeString("8b60969ccf00d52332b9fcea10da551a4bb1c7c2d3c12e36a602dedf35945016")
	// log.Printf("client keypair: %v", clientKeyPair)

	nowBytes := int64ToBytes(now.Unix())
	ct, nonce, err := publicKeyEncrypt(nowBytes, serverKeyPair.public, clientKeyPair.secret)
	// log.Printf("ct: %s, n: %s, err: %v", hex.EncodeToString(ct), hex.EncodeToString(nonce), err)
	tokenStruct := struct {
		Name string         `json:"n"`
		IAT  int64          `json:"iat"`
		EAT  encodableBytes `json:"eat"`
	}{
		Name: "arashpayan",
		IAT:  now.Unix(),
		EAT:  append(nonce, ct...),
	}
	tokenJSON, err := json.Marshal(tokenStruct)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("tokenJSON: %s", tokenJSON)

	tct, tno, err := symmetricKeyEncrypt(tokenJSON, serverSecretKey)
	if err != nil {
		log.Fatal(err)
	}
	// log.Printf("tct: %s, tno: %s, err: %v", hex.EncodeToString(tct), hex.EncodeToString(tno), err)
	eToken := append(tno, tct...)
	log.Printf("etoken length: %d, etoken base64 len: %d", len(eToken), len(base64.StdEncoding.EncodeToString(eToken)))
}
