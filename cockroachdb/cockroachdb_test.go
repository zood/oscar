package cockroachdb

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"sync"
	"testing"

	_ "github.com/lib/pq"
	"zood.xyz/oscar/relstor"
)

var cdb *cockroachDBProvider
var cdbOnce sync.Once

const createEmailVerificationTokensTable = `
CREATE TABLE IF NOT EXISTS email_verification_tokens (
	user_id SERIAL,
	token STRING(16) NOT NULL DEFAULT '',
	email STRING(254) NOT NULL DEFAULT '',
	send_date INT NOT NULL);`

const createMessagesTable = `
CREATE TABLE IF NOT EXISTS messages (
	id SERIAL,
	recipient_id INT NOT NULL,
	sender_id INT NOT NULL,
	cipher_text BYTES NOT NULL,
	nonce BYTES NOT NULL,
	sent_date INT NOT NULL);`

const createSessionChallengesTable = `
CREATE TABLE IF NOT EXISTS session_challenges (
	id SERIAL,
	user_id INT NOT NULL,
	creation_date INT NOT NULL,
	challenge BYTES NOT NULL);`

const createUserFcmTokensTable = `
CREATE TABLE IF NOT EXISTS user_fcm_tokens (
	id SERIAL,
	user_id INT NOT NULL,
	token STRING(256) NOT NULL DEFAULT '');`

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
	id SERIAL,
	username STRING(32) NOT NULL DEFAULT '',
	public_key BYTES NOT NULL,
	wrapped_secret_key BYTES NOT NULL,
	wrapped_secret_key_nonce BYTES NOT NULL,
	wrapped_symmetric_key BYTES NOT NULL,
	wrapped_symmetric_key_nonce BYTES NOT NULL,
	password_salt BYTES NOT NULL,
	password_hash_algorithm STRING(16) NOT NULL,
	password_hash_operations_limit INT NOT NULL,
	password_hash_memory_limit INT NOT NULL,
	email STRING(254) DEFAULT NULL);`

var dbTables = map[string]string{
	"users":                     createUsersTable,
	"user_fcm_tokens":           createUserFcmTokensTable,
	"session_challenges":        createSessionChallengesTable,
	"messages":                  createMessagesTable,
	"email_verification_tokens": createEmailVerificationTokensTable,
}

var alice relstor.UserRecord
var bob relstor.UserRecord

const aliceVerificationToken = "0123456789abcdef"
const bobVerificationToken = "fedcba9876543210"
const aliceFCMToken = "an-fcm-token-from-google"
const bobFCMToken = "an-fcm-token-for-bob"

var msgAB relstor.MessageRecord
var msgBA relstor.MessageRecord

func TestMain(m *testing.M) {
	// build the database tables

	db, err := sql.Open("postgres", "user=root dbname=oscarDb sslmode=disable port=26257") // "postgresql://root@127.0.0.1:26257?sslmode=disable"
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping: ", err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS oscarDb")
	if err != nil {
		log.Fatal("Failed to create database: ", err)
	}
	_, err = db.Exec("SET database = oscarDb")
	if err != nil {
		log.Fatal("Failed to set database to oscarDb: ", err)
	}

	// Create the tables
	for tbl, createSQL := range dbTables {
		_, err = db.Exec(createSQL)
		if err != nil {
			log.Fatalf("Failed to create '%s' table: %v", tbl, err)
		}
		// clear the table
		_, err = db.Exec("DELETE FROM " + tbl)
		if err != nil {
			log.Fatalf("Failed to delete data from table '%s': %v", tbl, err)
		}
	}

	// run the tests
	os.Exit(m.Run())
}

func db(t *testing.T) *cockroachDBProvider {
	var err error
	cdbOnce.Do(func() {
		cdb, err = New("postgresql://root@127.0.0.1:26257/oscarDb?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
	})

	if cdb == nil {
		t.Fatal("db was never initialized")
	}

	return cdb
}

func TestInsertUser(t *testing.T) {
	aliceEmail := "alice@gmail.com"
	aliceToken := aliceVerificationToken
	aliceUsername := "alice"
	alice = relstor.UserRecord{
		Email:                       &aliceEmail,
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("salt"),
		PublicKey:                   []byte("public key"),
		WrappedSecretKey:            []byte("wrapped secret key"),
		WrappedSecretKeyNonce:       []byte("wrapped secret key nonce"),
		WrappedSymmetricKey:         []byte("wrapped symmetric key"),
		WrappedSymmetricKeyNonce:    []byte("wrapped symmetric key nonce"),
		Username:                    aliceUsername,
	}
	var err error
	alice.ID, err = db(t).InsertUser(alice, &aliceToken)
	if err != nil {
		t.Fatalf("InsertUser failed: %v", err)
	}
	if alice.ID < 1 {
		t.Fatalf("InsertUser returned a bad user id: %d", alice.ID)
	}

	copy, err := db(t).User(aliceUsername)
	if err != nil {
		t.Fatalf("User() failed: %v", err)
	}

	if copy.Email != nil {
		t.Fatal("email should be nil after user insertion")
	}
	if copy.PasswordHashAlgorithm != alice.PasswordHashAlgorithm {
		t.Fatalf("%s != %s", copy.PasswordHashAlgorithm, alice.PasswordHashAlgorithm)
	}
	if copy.PasswordHashMemoryLimit != alice.PasswordHashMemoryLimit {
		t.Fatalf("%d != %d", copy.PasswordHashMemoryLimit, alice.PasswordHashMemoryLimit)
	}
	if copy.PasswordHashOperationsLimit != alice.PasswordHashOperationsLimit {
		t.Fatalf("%d != %d", copy.PasswordHashOperationsLimit, alice.PasswordHashOperationsLimit)
	}
	if !bytes.Equal(copy.PasswordSalt, alice.PasswordSalt) {
		t.Fatal("password salt does not match")
	}
	if copy.Username != alice.Username {
		t.Fatalf("%s != %s", copy.Username, alice.Username)
	}
	if !bytes.Equal(copy.WrappedSecretKey, alice.WrappedSecretKey) {
		t.Fatal("wrapped secret key doesn't match")
	}
	if !bytes.Equal(copy.WrappedSecretKeyNonce, alice.WrappedSecretKeyNonce) {
		t.Fatal("wrapped secret key nonce doesn't match")
	}
	if !bytes.Equal(copy.WrappedSymmetricKey, alice.WrappedSymmetricKey) {
		t.Fatal("wrapped symmetric key doesn't match")
	}
	if !bytes.Equal(copy.WrappedSymmetricKeyNonce, alice.WrappedSymmetricKeyNonce) {
		t.Fatal("wrapped symmetric key nonce doesn't match")
	}
	if copy.ID != alice.ID {
		t.Fatalf("id %d != %d", copy.ID, alice.ID)
	}
	if !bytes.Equal(copy.PublicKey, alice.PublicKey) {
		t.Fatal("public key does not match")
	}

	bobEmail := "bob@gmail.com"
	bobToken := bobVerificationToken
	bob = relstor.UserRecord{
		Email:                       &bobEmail,
		PasswordHashAlgorithm:       "argon2i13",
		PasswordHashMemoryLimit:     16384,
		PasswordHashOperationsLimit: 3,
		PasswordSalt:                []byte("bob's salt"),
		PublicKey:                   []byte("bob's public key"),
		WrappedSecretKey:            []byte("bob's wrapped secret key"),
		WrappedSecretKeyNonce:       []byte("bob's wrapped secret key nonce"),
		WrappedSymmetricKey:         []byte("bob's wrapped symmetric key"),
		WrappedSymmetricKeyNonce:    []byte("bob's wrapped symmetric key nonce"),
		Username:                    "bob",
	}
	bob.ID, err = db(t).InsertUser(bob, &bobToken)
	if err != nil {
		t.Fatal(err)
	}
}
