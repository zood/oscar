package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"zood.xyz/oscar/boltdb"
	"zood.xyz/oscar/filestor"
	"zood.xyz/oscar/mailgun"
	"zood.xyz/oscar/sqlite"

	"zood.xyz/oscar/gcs"
	"zood.xyz/oscar/localdisk"

	"golang.org/x/crypto/acme/autocert"

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

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	configPath := flag.String("config", "", "Path to config file")
	lvl := flag.Int("log-level", 4, "Controls the amount of info logged. Range from 1-4. Default is 4, errors only.")
	flag.Parse()

	if !validLogLevel(*lvl) {
		log.Fatalf("Invalid log level (%d). Must be between 1-4, inclusive.", *lvl)
	}

	currLogLevel = logLevel(*lvl)

	var err error
	config, err = applyConfigFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	rs, err := sqlite.New(config.SQLDSN)
	if err != nil {
		log.Fatalf("Unable to initialize sqlite db: %v", err)
	}

	kvs, err := boltdb.New(config.KVDBPath)
	if err != nil {
		log.Fatalf("Unable to initialize boltdb: %v", err)
	}

	var fs filestor.Provider
	switch config.FileStorage.Type {
	case "localdisk":
		fs, err = localdisk.New(config.FileStorage.LocalDiskStoragePath)
		if err != nil {
			log.Fatalf("Failed to create localdisk based filestor: %v", err)
		}
	case "gcs":
		fs, err = gcs.New(config.FileStorage.GCPCredentialsPath, config.FileStorage.GCPBucketName)
		if err != nil {
			log.Fatalf("Failed to create google cloud storage based filestor: %v", err)
		}
	default:
		log.Fatalf("Unknown filestor type: '%s'", config.FileStorage.Type)
	}

	r := mux.NewRouter()
	r.HandleFunc("/server-info", serverInfoHandler).Methods("GET")
	r.HandleFunc("/log-level", logLevelHandler).Methods("GET")
	r.HandleFunc("/log-level", setLogLevelHandler).Methods("PUT")
	alphaRouter := r.PathPrefix("/1").Subrouter()
	installEndPoints(alphaRouter)

	// playground()

	hostAddress := fmt.Sprintf(":%d", *config.Port)
	server := http.Server{
		Addr:         hostAddress,
		Handler:      providersInjector(fs, rs, kvs, logHandler(r)),
		ErrorLog:     log.New(&tlsHandshakeFilter{}, "", 0),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server for %s:%d", config.Hostname, *config.Port)
	if *config.TLS {
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
			HostPolicy: autocert.HostWhitelist(config.Hostname),
			Cache:      autocert.DirCache(config.AutocertDirCache),
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
	r.Handle("/users", sessionHandler(searchUsersHandler)).Methods("GET")
	r.HandleFunc("/users", sendEmailFuncInjector(mailgun.SendEmail, createUserHandler)).Methods("POST")
	r.Handle("/users/me/apns-tokens", sessionHandler(addAPNSTokenHandler)).Methods(http.MethodPost)
	r.Handle("/users/me/apns-tokens/{token}", sessionHandler(deleteAPNSTokenHandler)).Methods(http.MethodDelete)
	r.Handle("/users/me/fcm-tokens", sessionHandler(addFCMTokenHandler)).Methods("POST")
	r.Handle("/users/me/fcm-tokens/{token}", sessionHandler(deleteFCMTokenHandler)).Methods("DELETE")
	r.Handle("/users/me/backup", sessionHandler(retrieveBackupHandler)).Methods("GET")
	r.Handle("/users/me/backup", sessionHandler(saveBackupHandler)).Methods("PUT")
	r.Handle("/users/{public_id}", sessionHandler(getUserInfoHandler)).Methods("GET")
	r.Handle("/users/{public_id}/messages", sessionHandler(sendMessageToUserHandler)).Methods("POST")
	r.Handle("/users/{public_id}/public-key", corsHandler(getUserPublicKeyHandler)).Methods("GET")

	r.Handle("/messages", sessionHandler(getMessagesHandler)).Methods(http.MethodGet)
	r.Handle("/messages/{message_id:[0-9]+}", sessionHandler(getMessageHandler)).Methods(http.MethodGet)
	r.Handle("/messages/{message_id:[0-9]+}", sessionHandler(deleteMessageHandler)).Methods(http.MethodDelete)

	// this has to come first, so it has a chance to match before the box_id urls
	r.HandleFunc("/drop-boxes/watch", createPackageWatcherHandler).Methods("GET")
	r.Handle("/drop-boxes/send", sessionHandler(sendMultiplePackagesHandler)).Methods("POST")
	r.Handle("/drop-boxes/{box_id}", sessionHandler(pickUpPackageHandler)).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", sessionHandler(dropPackageHandler)).Methods("PUT")

	r.HandleFunc("/public-key", corsHandler(getServerPublicKeyHandler)).Methods("GET")

	r.Handle("/sessions/{username}/challenge", corsHandler(createAuthChallengeHandler)).Methods("POST")
	r.Handle("/sessions/{username}/challenge-response", corsHandler(finishAuthChallengeHandler)).Methods("POST")

	r.HandleFunc("/sockets", createSocketHandler).Methods(http.MethodGet)

	r.HandleFunc("/email-verifications", verifyEmailHandler).Methods("POST")
	r.HandleFunc("/email-verifications/{token}", disavowEmailHandler).Methods("DELETE")

	r.HandleFunc("/goroutine-stacks", goroutineStacksHandler).Methods("GET")
	// r.Handle("/test", logHandler(testHandler)).Methods("GET")
	r.HandleFunc("/logs", recordLogMessageHandler).Methods(http.MethodGet)
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
