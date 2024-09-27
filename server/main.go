package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	firebase "firebase.google.com/go/v4"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme/autocert"
	"google.golang.org/api/option"
	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/filestor"
	"zood.dev/oscar/gcs"
	"zood.dev/oscar/localdisk"
	"zood.dev/oscar/mailgun"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
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
	initLogging()

	configPath := flag.String("config", "", "Path to config file")
	debugLogs := flag.Bool("debug", false, "Enable debug logs")
	flag.Parse()

	if *debugLogs {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("loading config")
	}

	dsn := fmt.Sprintf("file:%s", filepath.Join(config.SQLDBDirectory, "sqlite.db"))
	rs, err := sqlite.New(dsn)
	if err != nil {
		log.Fatal().Err(err).Msg("opening sqlite db")
	}

	kvdbPath := filepath.Join(config.KVDBDirectory, "kv.db")
	kvs, err := boltdb.New(kvdbPath)
	if err != nil {
		log.Fatal().Err(err).Msg("opening boltdb")
	}

	var fs filestor.Provider
	switch config.FileStorage.Type {
	case "localdisk":
		fs, err = localdisk.New(config.FileStorage.LocalDiskStoragePath)
		if err != nil {
			log.Fatal().Err(err).Msg("createing localdisk based filestor")
		}
	case "gcs":
		fs, err = gcs.New(config.FileStorage.GCPCredentialsPath, config.FileStorage.GCPBucketName)
		if err != nil {
			log.Fatal().Err(err).Msg("creating google cloud storage based filestor")
		}
	default:
		log.Fatal().Str("fileStorageType", config.FileStorage.Type).Msg("unknown filestor type")
	}

	emailer := mailgun.New(config.Email.MailgunAPIKey, config.Email.Domain)

	fcmApp, err := firebase.NewApp(context.Background(), nil, option.WithCredentialsFile(config.FCMCredentialsPath))
	if err != nil {
		log.Fatal().Err(err).Msg("creating firebase app")
	}
	fcm, err := fcmApp.Messaging(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("creating firebase messaging client")
	}

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

	api := httpAPI{
		db:  rs,
		fcm: fcm,
		kvs: kvs,
	}
	router := newOscarRouter(providers, api)

	hostAddress := fmt.Sprintf(":%d", *config.Port)
	httpSrvr := http.Server{
		Addr:         hostAddress,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server for %s:%d", config.Hostname, *config.Port)
	if *config.TLS {
		tlsConfig := &tls.Config{}
		tlsConfig.CipherSuites = defaultCiphers
		tlsConfig.MinVersion = tls.VersionTLS12
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
		httpSrvr.TLSConfig = tlsConfig
		go http.ListenAndServe(":http", m.HTTPHandler(nil)) // this just runs for the sake of the autocert manager
		if err := httpSrvr.ListenAndServeTLS("", ""); err != nil {
			log.Fatal().Err(err).Msg("http.ListenAndServeTLS")
		}
	} else {
		if err := httpSrvr.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("http.ListenAndServe")
		}
	}
}

func newOscarRouter(p *serverProviders, api httpAPI) http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/server-info", serverInfoHandler).Methods(http.MethodGet, http.MethodOptions)
	r.HandleFunc("/enable-debug", api.enableDebugLoggingHandler).Methods(http.MethodGet)
	r.HandleFunc("/disable-debug", api.disableDebugLoggingHandler).Methods(http.MethodGet)
	v1 := r.PathPrefix("/1").Subrouter()

	v1.Handle("/users", sessionHandler(searchUsersHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.HandleFunc("/users", createUserHandler).Methods(http.MethodPost, http.MethodOptions)
	v1.Handle("/users/me/apns-tokens", sessionHandler(addAPNSTokenHandler)).Methods(http.MethodPost, http.MethodOptions)
	v1.Handle("/users/me/apns-tokens/{token}", sessionHandler(deleteAPNSTokenHandler)).Methods(http.MethodDelete, http.MethodOptions)
	v1.Handle("/users/me/fcm-tokens", sessionHandler(addFCMTokenHandler)).Methods(http.MethodPost, http.MethodOptions)
	v1.Handle("/users/me/fcm-tokens/{token}", sessionHandler(deleteFCMTokenHandler)).Methods(http.MethodDelete, http.MethodOptions)
	v1.Handle("/users/me/backup", sessionHandler(retrieveBackupHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/users/me/backup", sessionHandler(saveBackupHandler)).Methods(http.MethodPut, http.MethodOptions)
	v1.Handle("/users/{public_id}", sessionHandler(getUserInfoHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/users/{public_id}/messages", sessionHandler(api.sendMessageToUserHandler)).Methods(http.MethodPost, http.MethodOptions)
	v1.HandleFunc("/users/{public_id}/public-key", getUserPublicKeyHandler).Methods(http.MethodGet, http.MethodOptions)

	v1.Handle("/messages", sessionHandler(getMessagesHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/messages/{message_id:[0-9]+}", sessionHandler(getMessageHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/messages/{message_id:[0-9]+}", sessionHandler(deleteMessageHandler)).Methods(http.MethodDelete, http.MethodOptions)

	// this has to come first, so it has a chance to match before the box_id urls
	v1.HandleFunc("/drop-boxes/watch", createPackageWatcherHandler).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/drop-boxes/send", sessionHandler(sendMultiplePackagesHandler)).Methods(http.MethodPost, http.MethodOptions)
	v1.Handle("/drop-boxes/{box_id}", sessionHandler(pickUpPackageHandler)).Methods(http.MethodGet, http.MethodOptions)
	v1.Handle("/drop-boxes/{box_id}", sessionHandler(dropPackageHandler)).Methods(http.MethodPut, http.MethodOptions)

	v1.HandleFunc("/public-key", getServerPublicKeyHandler).Methods(http.MethodGet, http.MethodOptions)

	// We have to name the tickets endpoint with something that isn't a valid username, otherwise we would have just used /tickets
	v1.Handle("/sessions/expiring-tickets", sessionHandler(createTicketHandler)).Methods(http.MethodPost, http.MethodOptions)
	v1.HandleFunc("/sessions/{username}/challenge", createAuthChallengeHandler).Methods(http.MethodPost, http.MethodOptions)
	v1.HandleFunc("/sessions/{username}/challenge-response", finishAuthChallengeHandler).Methods(http.MethodPost, http.MethodOptions)

	v1.HandleFunc("/sockets", createSocketHandler).Methods(http.MethodGet, http.MethodOptions)

	v1.HandleFunc("/email-verifications", verifyEmailHandler).Methods(http.MethodPost, http.MethodOptions)
	v1.HandleFunc("/email-verifications/{token}", disavowEmailHandler).Methods(http.MethodDelete, http.MethodOptions)

	v1.HandleFunc("/goroutine-stacks", goroutineStacksHandler).Methods(http.MethodGet, http.MethodOptions)
	v1.HandleFunc("/logs", recordLogMessageHandler).Methods(http.MethodGet, http.MethodOptions)

	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)
	r.MethodNotAllowedHandler = http.HandlerFunc(notFoundHandler)

	r.Use(logMiddleware, corsMiddleware, p.Middleware)

	return r
}
