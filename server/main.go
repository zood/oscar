package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/filestor"
	"zood.dev/oscar/mailgun"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"

	"zood.dev/oscar/gcs"
	"zood.dev/oscar/localdisk"

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

	config, err := loadConfig(*configPath)
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

	emailer := mailgun.New(config.Email.MailgunAPIKey, config.Email.Domain)

	// playground()
	providers := &serverProviders{
		db:      rs,
		emailer: emailer,
		fs:      fs,
		kvs:     kvs,
		symKey:  config.SymmetricKey,
		keyPair: sodium.KeyPair{
			Public: config.AsymmetricKeys.Public,
			Secret: config.AsymmetricKeys.Secret,
		},
	}
	router := newOscarRouter(providers)

	hostAddress := fmt.Sprintf(":%d", *config.Port)
	server := http.Server{
		Addr:         hostAddress,
		Handler:      router,
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

func newOscarRouter(p *serverProviders) http.HandlerFunc {
	r := mux.NewRouter()
	r.HandleFunc("/server-info", serverInfoHandler).Methods("GET")
	r.HandleFunc("/log-level", logLevelHandler).Methods("GET")
	r.HandleFunc("/log-level", setLogLevelHandler).Methods("PUT")
	v1 := r.PathPrefix("/1").Subrouter()

	v1.Handle("/users", sessionHandler(searchUsersHandler)).Methods("GET")
	v1.HandleFunc("/users", createUserHandler).Methods(http.MethodPost)
	v1.Handle("/users/me/apns-tokens", sessionHandler(addAPNSTokenHandler)).Methods(http.MethodPost)
	v1.Handle("/users/me/apns-tokens/{token}", sessionHandler(deleteAPNSTokenHandler)).Methods(http.MethodDelete)
	v1.Handle("/users/me/fcm-tokens", sessionHandler(addFCMTokenHandler)).Methods("POST")
	v1.Handle("/users/me/fcm-tokens/{token}", sessionHandler(deleteFCMTokenHandler)).Methods("DELETE")
	v1.Handle("/users/me/backup", sessionHandler(retrieveBackupHandler)).Methods("GET")
	v1.Handle("/users/me/backup", sessionHandler(saveBackupHandler)).Methods("PUT")
	v1.Handle("/users/{public_id}", sessionHandler(getUserInfoHandler)).Methods("GET")
	v1.Handle("/users/{public_id}/messages", sessionHandler(sendMessageToUserHandler)).Methods("POST")
	v1.Handle("/users/{public_id}/public-key", corsHandler(getUserPublicKeyHandler)).Methods("GET")

	v1.Handle("/messages", sessionHandler(getMessagesHandler)).Methods(http.MethodGet)
	v1.Handle("/messages/{message_id:[0-9]+}", sessionHandler(getMessageHandler)).Methods(http.MethodGet)
	v1.Handle("/messages/{message_id:[0-9]+}", sessionHandler(deleteMessageHandler)).Methods(http.MethodDelete)

	// this has to come first, so it has a chance to match before the box_id urls
	v1.HandleFunc("/drop-boxes/watch", createPackageWatcherHandler).Methods("GET")
	v1.Handle("/drop-boxes/send", sessionHandler(sendMultiplePackagesHandler)).Methods("POST")
	v1.Handle("/drop-boxes/{box_id}", sessionHandler(pickUpPackageHandler)).Methods("GET")
	v1.Handle("/drop-boxes/{box_id}", sessionHandler(dropPackageHandler)).Methods("PUT")

	v1.HandleFunc("/public-key", corsHandler(getServerPublicKeyHandler)).Methods("GET")

	// We have to name the tickets endpoint with something that isn't a valid username, otherwise we would have just used /tickets
	v1.Handle("/sessions/expiring-tickets", corsHandler(sessionHandler(createTicketHandler))).Methods(http.MethodPost)
	v1.Handle("/sessions/{username}/challenge", corsHandler(createAuthChallengeHandler)).Methods("POST")
	v1.Handle("/sessions/{username}/challenge-response", corsHandler(finishAuthChallengeHandler)).Methods("POST")

	v1.HandleFunc("/sockets", createSocketHandler).Methods(http.MethodGet)

	v1.HandleFunc("/email-verifications", verifyEmailHandler).Methods("POST")
	v1.HandleFunc("/email-verifications/{token}", disavowEmailHandler).Methods("DELETE")

	v1.HandleFunc("/goroutine-stacks", goroutineStacksHandler).Methods("GET")
	// r.Handle("/test", logHandler(testHandler)).Methods("GET")
	v1.HandleFunc("/logs", recordLogMessageHandler).Methods(http.MethodGet)

	return providersInjector(p, logHandler(r))

	// return providersInjector(p.fs, p.db, p.kvs, logHandler(r))
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
