package mariadb

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"pijun.io/oscar/relstor"

	_ "github.com/go-sql-driver/mysql"
)

var mdb relstor.Provider
var mdbOnce sync.Once

var sqlDSN = "root:badpassword@tcp(127.0.0.1:3306)/pijunDb?parseTime=true&loc=UTC"

const createEmailVerificationTokensTable = `
CREATE TABLE IF NOT EXISTS email_verification_tokens (
	user_id int(11) unsigned NOT NULL,
	token char(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
	email varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
	send_date int(11) NOT NULL,
	PRIMARY KEY (user_id)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

const createMessagesTable = `
CREATE TABLE IF NOT EXISTS messages (
	id int(11) unsigned NOT NULL AUTO_INCREMENT,
	recipient_id int(11) NOT NULL,
	sender_id int(11) NOT NULL,
	cipher_text mediumblob NOT NULL,
	nonce blob NOT NULL,
	sent_date bigint(11) NOT NULL,
	PRIMARY KEY (id)
  ) ENGINE=InnoDB AUTO_INCREMENT=33 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

const createSessionChallengesTable = `
CREATE TABLE IF NOT EXISTS session_challenges (
	id int(11) unsigned NOT NULL AUTO_INCREMENT,
	user_id int(11) NOT NULL,
	creation_date int(11) NOT NULL,
	challenge tinyblob NOT NULL,
	PRIMARY KEY (id)
  ) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

const createUserFcmTokensTable = `
CREATE TABLE IF NOT EXISTS user_fcm_tokens (
	id int(11) unsigned NOT NULL AUTO_INCREMENT,
	user_id int(11) NOT NULL,
	token varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
	PRIMARY KEY (id)
  ) ENGINE=InnoDB AUTO_INCREMENT=91 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
	id int(11) unsigned NOT NULL AUTO_INCREMENT,
	username varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '',
	public_key blob NOT NULL,
	wrapped_secret_key blob NOT NULL,
	wrapped_secret_key_nonce blob NOT NULL,
	wrapped_symmetric_key blob NOT NULL,
	wrapped_symmetric_key_nonce blob NOT NULL,
	password_salt blob NOT NULL,
	password_hash_algorithm varchar(16) COLLATE utf8_unicode_ci DEFAULT NULL,
	password_hash_operations_limit bigint(11) NOT NULL,
	password_hash_memory_limit bigint(11) NOT NULL,
	email varchar(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
	PRIMARY KEY (id)
  ) ENGINE=InnoDB AUTO_INCREMENT=46 DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;`

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

	db, err := sql.Open("mysql", "root:badpassword@tcp(127.0.0.1:3306)/?parseTime=true&loc=UTC")
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal("Failed to ping: ", err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS pijunDb")
	if err != nil {
		log.Fatal("Failed to create database: ", err)
	}
	_, err = db.Exec("USE pijunDb")
	if err != nil {
		log.Fatal("Failed to use/switch to pijunDb: ", err)
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

func db(t *testing.T) relstor.Provider {
	var err error
	mdbOnce.Do(func() {
		mdb, err = New(sqlDSN)
		if err != nil {
			t.Fatal(err)
		}
	})

	if mdb == nil {
		t.Fatal("db was never initialized")
	}

	return mdb
}

func TestInsertUser(t *testing.T) {
	aliceEmail := "alice@gmail.com"
	aliceToken := aliceVerificationToken
	aliceUsername := "alice"
	alice = relstor.UserRecord{
		Email: &aliceEmail,
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
		Email: &bobEmail,
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

func TestGetInvalidUser(t *testing.T) {
	record, err := db(t).User("zed")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("Should not have received a record. Got %+v", record)
	}
}

func TestLimitedUserInfo(t *testing.T) {
	userID, pubKey, err := db(t).LimitedUserInfo(alice.Username)
	if err != nil {
		t.Fatal(err)
	}
	if userID != alice.ID {
		t.Fatalf("id %d != %d", userID, alice.ID)
	}
	if !bytes.Equal(pubKey, alice.PublicKey) {
		t.Fatal("public key does not match")
	}

	// check how it behaves when you give it a bad username
	userID, pubKey, err = db(t).LimitedUserInfo("notauser")
	if err != nil {
		t.Fatal(err)
	}
	if userID != 0 {
		t.Fatal("user id should be 0")
	}
	if pubKey != nil {
		t.Fatal("public key should be nil")
	}
}

func TestLimitedUserInfoID(t *testing.T) {
	username, pubKey, err := db(t).LimitedUserInfoID(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if username != alice.Username {
		t.Fatalf("%s != %s", username, alice.Username)
	}
	if !bytes.Equal(pubKey, alice.PublicKey) {
		t.Fatal("public key does not match")
	}

	// make sure it gives not found values when you give an invalid id
	username, pubKey, err = db(t).LimitedUserInfoID(-1)
	if err != nil {
		t.Fatal(err)
	}
	if username != "" {
		t.Fatalf("Should have received an empty username. Got '%s'", username)
	}
	if pubKey != nil {
		t.Fatal("public key should be nil")
	}
}

func TestGetUsername(t *testing.T) {
	username := db(t).Username(alice.ID)
	if username != alice.Username {
		t.Fatalf("%s != %s", username, alice.Username)
	}

	username = db(t).Username(-1)
	if username != "" {
		t.Fatalf("username should be empty. is %s", username)
	}
}

func TestUsernameAvailable(t *testing.T) {
	available, err := db(t).UsernameAvailable(alice.Username)
	if err != nil {
		t.Fatal(err)
	}
	if available {
		t.Fatal("username should NOT be available")
	}

	available, err = db(t).UsernameAvailable("abbiedoobie")
	if err != nil {
		t.Fatal(err)
	}
	if !available {
		t.Fatal("username SHOULD be available")
	}
}

func TestUserPublicKey(t *testing.T) {
	pubKey, err := db(t).UserPublicKey(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubKey, alice.PublicKey) {
		t.Fatal("public key does not match")
	}

	// test the bad case
	pubKey, err = db(t).UserPublicKey(-1)
	if err != nil {
		t.Fatal(err)
	}
	if pubKey != nil {
		t.Fatal("public key should be nil")
	}
}

func TestInsertMessage(t *testing.T) {
	msgAB = relstor.MessageRecord{
		RecipientID: bob.ID,
		SenderID:    alice.ID,
		CipherText:  []byte("Alice to Bob cipher text"),
		Nonce:       []byte("Alice to Bob nonce"),
		SentDate:    time.Now().Unix(),
	}

	var err error
	msgAB.ID, err = db(t).InsertMessage(msgAB.RecipientID, msgAB.SenderID, msgAB.CipherText, msgAB.Nonce, msgAB.SentDate)
	if err != nil {
		t.Fatal(err)
	}
	if msgAB.ID < 1 {
		t.Fatal("bad id for msg from alice to bob")
	}

	msgBA = relstor.MessageRecord{
		RecipientID: alice.ID,
		SenderID:    bob.ID,
		CipherText:  []byte("Bob to Alice cipher text"),
		Nonce:       []byte("Bob to Alice nonce"),
		SentDate:    time.Now().Unix(),
	}

	msgBA.ID, err = db(t).InsertMessage(msgBA.RecipientID, msgBA.SenderID, msgBA.CipherText, msgBA.Nonce, msgBA.SentDate)
	if err != nil {
		t.Fatal(err)
	}
	if msgBA.ID < 1 {
		t.Fatal("bad if ro msg from bob to alice")
	}
}

func TestMessageToRecipient(t *testing.T) {
	// test the bad case
	copy, err := db(t).MessageToRecipient(alice.ID, msgAB.ID) // incorrect message id
	if err != nil {
		t.Fatal(err)
	}
	if copy != nil {
		t.Fatal("msg should be nil")
	}

	// test the good case
	copy, err = db(t).MessageToRecipient(alice.ID, msgBA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if copy == nil {
		t.Fatal("msg came back nil")
	}
	if copy.ID != msgBA.ID {
		t.Fatalf("msg id %d != %d", copy.ID, msgBA.ID)
	}
	if copy.RecipientID != msgBA.RecipientID {
		t.Fatalf("recip id %d != %d", copy.RecipientID, msgBA.RecipientID)
	}
	if copy.SenderID != msgBA.SenderID {
		t.Fatalf("sender id %d != %d", copy.SenderID, msgBA.SenderID)
	}
	if copy.SentDate != msgBA.SentDate {
		t.Fatalf("sent date %d != %d", copy.SentDate, msgBA.SentDate)
	}
	if !bytes.Equal(copy.CipherText, msgBA.CipherText) {
		t.Fatal("cipher text is not equal")
	}
	if !bytes.Equal(copy.Nonce, msgBA.Nonce) {
		t.Fatal("nonce is not equal")
	}
}

func TestMessageRecords(t *testing.T) {
	msgs, err := db(t).MessageRecords(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("Expecting 1 message, but found %d", len(msgs))
	}
	copy := msgs[0]
	if copy.ID != msgAB.ID {
		t.Fatalf("msg id %d != %d", copy.ID, msgAB.ID)
	}
	if copy.RecipientID != msgAB.RecipientID {
		t.Fatalf("recip id %d != %d", copy.RecipientID, msgAB.RecipientID)
	}
	if copy.SenderID != msgAB.SenderID {
		t.Fatalf("sender id %d != %d", copy.SenderID, msgAB.SenderID)
	}
	if copy.SentDate != msgAB.SentDate {
		t.Fatalf("sent date %d != %d", copy.SentDate, msgAB.SentDate)
	}
	if !bytes.Equal(copy.CipherText, msgAB.CipherText) {
		t.Fatal("cipher text is not equal")
	}
	if !bytes.Equal(copy.Nonce, msgAB.Nonce) {
		t.Fatal("nonce is not equal")
	}
}

func TestEmailVerificationTokenRecord(t *testing.T) {
	record, err := db(t).EmailVerificationTokenRecord(aliceVerificationToken)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("email verification token record is nil")
	}
	if record.Email != *alice.Email {
		t.Fatalf("%s != %s", record.Email, *alice.Email)
	}
	if record.SendDate == 0 {
		t.Fatal("A send date was not created for the email verification token record")
	}
	if record.Token != aliceVerificationToken {
		t.Fatalf("token mismatch: %s != %s", record.Token, aliceVerificationToken)
	}
	if record.UserID != alice.ID {
		t.Fatalf("user id mismatch: %d != %d", record.UserID, alice.ID)
	}

	// test the bad case
	record, err = db(t).EmailVerificationTokenRecord("deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatal("email verification token record should be nil")
	}
}

func TestVerifyEmail(t *testing.T) {
	err := db(t).VerifyEmail(*alice.Email, alice.ID)
	if err != nil {
		t.Fatal(err)
	}

	user, err := db(t).User(alice.Username)
	if err != nil {
		t.Fatal(err)
	}
	if user.Email == nil {
		t.Fatal("email is still nil after verification")
	}
	if *user.Email != *alice.Email {
		t.Fatalf("email does not match after verification: %s != %s", *user.Email, *alice.Email)
	}

	// make sure the verification record is no longer present
	record, err := db(t).EmailVerificationTokenRecord(aliceVerificationToken)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("received a record, when it should have been nil: %+v", record)
	}
}

func TestDisavowEmail(t *testing.T) {
	// Bob will disavow the email address
	err := db(t).DisavowEmail(bobVerificationToken)
	if err != nil {
		t.Fatal(err)
	}

	// the email verification record should no longer be present
	record, err := db(t).EmailVerificationTokenRecord(bobVerificationToken)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("email verification token record should not exist after disavowing email. found %+v", record)
	}
}

func TestDeleteMessageToRecipient(t *testing.T) {
	err := db(t).DeleteMessageToRecipient(alice.ID, msgBA.ID)
	if err != nil {
		t.Fatal(err)
	}

	// make sure the message no longer exists in the database
	msg, err := db(t).MessageToRecipient(alice.ID, msgBA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if msg != nil {
		t.Fatalf("message should have been nil after deleting. found %+v", msg)
	}
}

func TestSessionChallenge(t *testing.T) {
	challenge := []byte("this is a challenge")
	creationDate := time.Now().Unix()
	err := db(t).InsertSessionChallenge(alice.ID, creationDate, challenge)
	if err != nil {
		t.Fatal(err)
	}

	scRec, err := db(t).SessionChallenge(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scRec == nil {
		t.Fatalf("session challenge record is nil")
	}
	if scRec.ID < 1 {
		t.Fatalf("Invalid id. Found: %d", scRec.ID)
	}
	if scRec.UserID != alice.ID {
		t.Fatalf("Mismatched user id: %d != %d", scRec.UserID, alice.ID)
	}
	if scRec.CreationDate != creationDate {
		t.Fatalf("Incorrect creationDate: %d != %d", scRec.CreationDate, creationDate)
	}
	if !bytes.Equal(challenge, scRec.Challenge) {
		t.Fatalf("challenge doesn't match")
	}

	err = db(t).DeleteSessionChallengeUser(alice.ID)
	if err != nil {
		t.Fatal(err)
	}

	// try to receive the challenge. It should be gone.
	scRec, err = db(t).SessionChallenge(alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scRec != nil {
		t.Fatalf("The session challenge should not exist. Found %+v", scRec)
	}
}

func TestDeleteSessionChallengeID(t *testing.T) {
	challenge := []byte("a different challenge")
	creationDate := time.Now().Unix()
	err := db(t).InsertSessionChallenge(bob.ID, creationDate, challenge)
	if err != nil {
		t.Fatal(err)
	}

	// retrieve the challenge
	scRec, err := db(t).SessionChallenge(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scRec == nil {
		t.Fatal("challenge is missing after insertion")
	}

	// now delete it
	err = db(t).DeleteSessionChallengeID(scRec.ID)
	if err != nil {
		t.Fatal(err)
	}

	// retrieving the challenge should fail
	scRec, err = db(t).SessionChallenge(bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scRec != nil {
		t.Fatalf("Deleting session challenge failed. Still got %+v in return.", scRec)
	}
}

func TestInsertAndGetFCMToken(t *testing.T) {
	err := db(t).InsertFCMToken(alice.ID, aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}

	// now try to retrieve it
	record, err := db(t).FCMToken(aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("Unable to retrieve FCM token")
	}
	if record.ID < 1 {
		t.Fatalf("Invalid id for FCM token record: %d", record.ID)
	}
	if record.Token != aliceFCMToken {
		t.Fatalf("Token does not match: %s != %s", record.Token, aliceFCMToken)
	}
	if record.UserID != alice.ID {
		t.Fatalf("User id does not match: %d != %d", record.UserID, alice.ID)
	}

	// now try to retrieve it another way
	record, err = db(t).FCMTokenUser(alice.ID, aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatalf("Unable to retrieve FCM token")
	}
	if record.ID < 1 {
		t.Fatalf("Invalid id for FCM token record: %d", record.ID)
	}
	if record.Token != aliceFCMToken {
		t.Fatalf("Token does not match: %s != %s", record.Token, aliceFCMToken)
	}
	if record.UserID != alice.ID {
		t.Fatalf("User id does not match: %d != %d", record.UserID, alice.ID)
	}
}

func TestGetFCMTokenInvalid(t *testing.T) {
	token := "not-a-real-token"
	record, err := db(t).FCMToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("Should not have received a record. Got %+v", record)
	}

	// Bob's user id, but alice's token
	record, err = db(t).FCMTokenUser(bob.ID, aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("Should not have received a record. Got %+v", record)
	}
}

func TestUpdateUserIDofFCMToken(t *testing.T) {
	// Alice has logged out of her phone, and Bob has logged in, thus taking over the device's FCM token
	err := db(t).UpdateUserIDOfFCMToken(bob.ID, aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}

	// make sure we get the correct record now when we retrieve it
	record, err := db(t).FCMToken(aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("FCM token record should not be nil")
	}
	if record.Token != aliceFCMToken {
		t.Fatalf("token mismatch: %s != %s", record.Token, aliceFCMToken)
	}
	if record.UserID != bob.ID {
		t.Fatalf("user id mismatch: %d != %d", record.UserID, bob.ID)
	}
}

func TestReplaceFCMToken(t *testing.T) {
	// Now that Bob has logged in to the device, time has passed and his FCM token has been updated
	rowsAffected, err := db(t).ReplaceFCMToken(aliceFCMToken, bobFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if rowsAffected != 1 {
		t.Fatalf("Rows affected was not 1. Was %d", rowsAffected)
	}

	// make sure we get the correct record when retrieving it
	record, err := db(t).FCMToken(bobFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("FCM token record should not be nil")
	}
	if record.Token != bobFCMToken {
		t.Fatalf("token mismatch: %s != %s", record.Token, aliceFCMToken)
	}
	if record.UserID != bob.ID {
		t.Fatalf("user id mismatch: %d != %d", record.UserID, bob.ID)
	}
}

func TestDeleteFCMTokenOfUser(t *testing.T) {
	err := db(t).DeleteFCMTokenOfUser(bob.ID, bobFCMToken)
	if err != nil {
		t.Fatal(err)
	}

	// make sure it can't be retrieved
	record, err := db(t).FCMToken(bobFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("FCM token should be nil. Found %+v", record)
	}
}

func TestDeleteFCMToken(t *testing.T) {
	// insert a token for alice, then delete it
	err := db(t).InsertFCMToken(alice.ID, aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}

	err = db(t).DeleteFCMToken(aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}

	// we should not be able to retrieve the token record anymore
	record, err := db(t).FCMToken(aliceFCMToken)
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("FCM token should be nil. Found %+v", record)
	}
}
