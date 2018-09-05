package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"zood.xyz/oscar/filestor"
	"zood.xyz/oscar/kvstor"

	"golang.org/x/crypto/acme/autocert"
	"zood.xyz/oscar/relstor"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

var rs relstor.Provider
var kvs kvstor.Provider
var fs filestor.Provider

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	configPath := flag.String("config", "", "Path to config file")
	lvl := flag.Int("log-level", 4, "Controls the amount of info logged. Range from 1-4. Default is 4, errors only.")
	flag.Parse()

	if !validLogLevel(*lvl) {
		log.Fatalf("Invalid log level (%d). Must be between 1-4, inclusive.", *lvl)
	}

	currLogLevel = logLevel(*lvl)

	cfg, err := applyConfigFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.Handle("/server-info", logHandler(serverInfoHandler)).Methods("GET")
	r.Handle("/log-level", logHandler(logLevelHandler)).Methods("GET")
	r.Handle("/log-level", logHandler(setLogLevelHandler)).Methods("PUT")
	alphaRouter := r.PathPrefix("/alpha").Subrouter()
	installEndPoints(alphaRouter)

	// playground()

	hostAddress := fmt.Sprintf(":%d", *cfg.Port)
	server := http.Server{
		Addr:         hostAddress,
		Handler:      r,
		ErrorLog:     log.New(&tlsHandshakeFilter{}, "", 0),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server for %s:%d", cfg.Hostname, *cfg.Port)
	if *cfg.TLS {
		tlsConfig := &tls.Config{}
		tlsConfig.CipherSuites = defaultCiphers
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.PreferServerCipherSuites = true
		tlsConfig.CurvePreferences = []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		}
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Hostname),
			Cache:      autocert.DirCache("./"),
		}
		tlsConfig.GetCertificate = m.GetCertificate
		server.TLSConfig = tlsConfig
		go http.ListenAndServe(":http", m.HTTPHandler(nil)) // this just runs for the sake of the autocert manager
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func installEndPoints(r *mux.Router) {
	r.Handle("/users", logHandler(sessionHandler(searchUsersHandler))).Methods("GET")
	r.Handle("/users", logHandler(createUserHandler)).Methods("POST")
	r.Handle("/users/me/apns-tokens", logHandler(sessionHandler(addAPNSTokenHandler))).Methods(http.MethodPost)
	r.Handle("/users/me/apns-tokens/{token}", logHandler(sessionHandler(deleteAPNSTokenHandler))).Methods(http.MethodDelete)
	r.Handle("/users/me/fcm-tokens", logHandler(sessionHandler(addFCMTokenHandler))).Methods("POST")
	r.Handle("/users/me/fcm-tokens/{token}", logHandler(sessionHandler(deleteFCMTokenHandler))).Methods("DELETE")
	r.Handle("/users/me/backup", logHandler(sessionHandler(retrieveBackupHandler))).Methods("GET")
	r.Handle("/users/me/backup", logHandler(sessionHandler(saveBackupHandler))).Methods("PUT")
	r.Handle("/users/{public_id}", logHandler(sessionHandler(getUserInfoHandler))).Methods("GET")
	r.Handle("/users/{public_id}/messages", logHandler(sessionHandler(sendMessageToUserHandler))).Methods("POST")
	r.Handle("/users/{public_id}/public-key", logHandler(corsHandler(getUserPublicKeyHandler))).Methods("GET")

	r.Handle("/messages", logHandler(sessionHandler(getMessagesHandler))).Methods(http.MethodGet)
	r.Handle("/messages/{message_id:[0-9]+}", logHandler(sessionHandler(getMessageHandler))).Methods(http.MethodGet)
	r.Handle("/messages/{message_id:[0-9]+}", logHandler(sessionHandler(deleteMessageHandler))).Methods(http.MethodDelete)

	// this has to come first, so it has a chance to match before the box_id urls
	r.Handle("/drop-boxes/watch", logHandler(createPackageWatcherHandler)).Methods("GET")
	r.Handle("/drop-boxes/send", logHandler(sessionHandler(sendMultiplePackagesHandler))).Methods("POST")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(pickUpPackageHandler))).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(dropPackageHandler))).Methods("PUT")

	r.Handle("/public-key", logHandler(getServerPublicKeyHandler)).Methods("GET")

	r.Handle("/sessions/{username}/challenge", logHandler(corsHandler(createAuthChallengeHandler))).Methods("POST")
	r.Handle("/sessions/{username}/challenge-response", logHandler(corsHandler(finishAuthChallengeHandler))).Methods("POST")

	r.Handle("/sockets", logHandler(createSocketHandler)).Methods(http.MethodGet)

	r.Handle("/email-verifications", logHandler(verifyEmailHandler)).Methods("POST")
	r.Handle("/email-verifications/{token}", logHandler(disavowEmailHandler)).Methods("DELETE")

	r.Handle("/goroutine-stacks", logHandler(goroutineStacksHandler)).Methods("GET")
	// r.Handle("/test", logHandler(testHandler)).Methods("GET")
	r.Handle("/logs", logHandler(recordLogMessageHandler)).Methods(http.MethodGet)
}

func testHandler(w http.ResponseWriter, r *http.Request) {
}

type tlsHandshakeFilter struct{}

func (dl *tlsHandshakeFilter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error from")) {
		return len(p), nil // lie to the caller
	}

	log.Printf("%s", p)
	return len(p), nil
}

func playground() {
}
