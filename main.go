package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/hex"
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

	playground()

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
	r.Handle("/sessions/{username}/challenge-response", logHandler(finishAuthChallengeHandler)).Methods("POST")

	r.Handle("/goroutine-stacks", logHandler(goroutineStacksHandler)).Methods("GET")
	r.Handle("/test", logHandler(testHandler)).Methods("GET")
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	// pushMessageToUser(22, 16)
	sendFirebaseMessage(16, nil, false)
}

func playground() {
	symKey := make([]byte, secretBoxKeySize)
	crand.Read(symKey)
	log.Printf("symKey: %s", hex.EncodeToString(symKey))

	skp, err := generateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server keypair: %v", skp)
}
