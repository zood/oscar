package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

// Debug contains whether the server is running in debug mode
var Debug = false

var defaultCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	port := flag.Int("port", 80, "Listening port for server")
	debug := flag.Bool("debug", false, "Enables additional log output")
	sqlDSN := flag.String(
		"sqldsn",
		"",
		"DSN to SQL server e.g. username:password@protocol(address)/dbname?param=value")
	kvDBPath := flag.String("kvdb", "", "Path to key-value database file")
	backupsPath := flag.String("backups", "", "Path to store user database backup files")
	tlsKey := flag.String("tls-key", "", "Path to TLS key file")
	tlsCert := flag.String("tls-cert", "", "Path to TLS cert file")
	flag.Parse()
	Debug = *debug

	gFCMServerKey = os.Getenv("FCM_SERVER_KEY")
	if gFCMServerKey == "" {
		log.Fatal("$FCM_SERVER_KEY is missing/empty")
	}

	err := initDB(*sqlDSN)
	if err != nil {
		log.Fatalf("Error initializing SQL db: %v", err)
	}

	err = initKVDB(*kvDBPath)
	if err != nil {
		log.Fatalf("Error initializing key-value db: %v", err)
	}

	if *backupsPath == "" {
		log.Fatal("user database backups path is empty")
	}
	userDBBackupFiles = *backupsPath

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
	if *tlsCert != "" && *tlsKey != "" {
		tlsConfig := &tls.Config{}
		tlsConfig.CipherSuites = defaultCiphers
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
		tlsConfig.PreferServerCipherSuites = true
		server.TLSConfig = tlsConfig
		log.Fatal(server.ListenAndServeTLS(*tlsCert, *tlsKey))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func installEndPoints(r *mux.Router) {
	r.Handle("/users", logHandler(sessionHandler(http.HandlerFunc(searchUsersHandler)))).Methods("GET")
	r.Handle("/users", logHandler(http.HandlerFunc(createUserHandler))).Methods("POST")
	r.Handle("/users/me/fcm-tokens", logHandler(sessionHandler(http.HandlerFunc(addFCMTokenHandler)))).Methods("POST")
	r.Handle("/users/me/fcm-tokens/{token}", logHandler(sessionHandler(http.HandlerFunc(deleteFCMTokenHandler)))).Methods("DELETE")
	r.Handle("/users/me/backup", logHandler(sessionHandler(http.HandlerFunc(retrieveBackupHandler)))).Methods("GET")
	r.Handle("/users/me/backup", logHandler(sessionHandler(http.HandlerFunc(saveBackupHandler)))).Methods("PUT")
	r.Handle("/users/{public_id}", logHandler(sessionHandler(http.HandlerFunc(getUserInfoHandler)))).Methods("GET")
	r.Handle("/users/{public_id}/messages", logHandler(sessionHandler(http.HandlerFunc(sendMessageToUserHandler)))).Methods("POST")
	r.Handle("/users/{public_id}/public-key", logHandler(sessionHandler(http.HandlerFunc(getUserPublicKeyHandler)))).Methods("GET")

	r.Handle("/messages", logHandler(sessionHandler(http.HandlerFunc(getMessagesHandler)))).Methods("GET")
	r.Handle("/messages/{message_id:[0-9]+}", logHandler(sessionHandler(http.HandlerFunc(deleteMessageHandler)))).Methods("DELETE")

	// this has to come first, so it has a chance to match before the box_id urls
	r.Handle("/drop-boxes/watch", logHandler(sessionHandler(http.HandlerFunc(createPackageWatcherHandler)))).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(http.HandlerFunc(pickUpPackageHandler)))).Methods("GET")
	r.Handle("/drop-boxes/{box_id}", logHandler(sessionHandler(http.HandlerFunc(dropPackageHandler)))).Methods("PUT")

	r.Handle("/sessions/{username}/challenge", logHandler(http.HandlerFunc(createAuthChallengeHandler))).Methods("POST")
	r.Handle("/sessions/{username}/challenge-response", logHandler(http.HandlerFunc(authChallengeResponseHandler))).Methods("POST")

	r.Handle("/goroutine-stacks", logHandler(http.HandlerFunc(goroutineStacksHandler))).Methods("GET")
	r.Handle("/test", logHandler(http.HandlerFunc(testHandler))).Methods("GET")
}

func testHandler(w http.ResponseWriter, r *http.Request) {
	// pushMessageToUser(22, 16)
	sendFirebaseMessage(16, nil, false)
}

func playground() {
	// rdr := bytes.NewReader([]byte{'w', 'o', 'r', 'd'})
	// var token string
	// err := json.NewDecoder(rdr).Decode(&token)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// log.Printf("decoded: %v", token)
}
