package sqlite

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/relstor"
)

func newDB(t *testing.T) sqliteDB {
	t.Helper()

	db, err := New(InMemoryDSN)
	require.NoError(t, err)
	return db.(sqliteDB)
}

func TestEmailVerification(t *testing.T) {
	db := newDB(t)

	email := "foo@zood.xyz"
	user := relstor.UserRecord{
		Email:                       &email,
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "bob",
	}
	verificationToken := "some-secret-token-used-for-verification"

	var err error
	user.ID, err = db.InsertUser(user, &verificationToken)
	require.NoError(t, err)
	require.Greater(t, user.ID, int64(0))

	tokenRecord, err := db.EmailVerificationTokenRecord(verificationToken)
	require.NoError(t, err)
	require.NotNil(t, tokenRecord)
	require.Equal(t, tokenRecord.Email, email)
	require.Equal(t, verificationToken, tokenRecord.Token)
	require.Equal(t, user.ID, tokenRecord.UserID)
	// make sure the send date is within the last 5 seconds
	require.LessOrEqual(t, tokenRecord.SendDate, time.Now().Unix())
	require.Greater(t, tokenRecord.SendDate, time.Now().Unix()-5)

	// using a bad user id
	err = db.VerifyEmail(email, 5000)
	require.NoError(t, err)

	// the verification token record should still exist
	tr2, err := db.EmailVerificationTokenRecord(verificationToken)
	require.NoError(t, err)
	require.Equal(t, tokenRecord, tr2)

	// use the correct user id this time
	err = db.VerifyEmail(email, user.ID)
	require.NoError(t, err)

	// the verification token record should be gone
	tr2, err = db.EmailVerificationTokenRecord(verificationToken)
	require.NoError(t, err)
	require.Nil(t, tr2)

	// the user record should now contain an emailaddress
	user.Email = &email
	actual, err := db.User(user.Username)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, user, *actual)
}

func TestDisavowEmail(t *testing.T) {
	db := newDB(t)

	email := "foo@zood.xyz"
	user := relstor.UserRecord{
		Email:                       &email,
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "bob",
	}
	verificationToken := "some-secret-token-used-for-verification"
	var err error
	user.ID, err = db.InsertUser(user, &verificationToken)
	require.NoError(t, err)

	err = db.DisavowEmail("not-a-valid-token")
	require.NoError(t, err)

	// the token record should still exist
	tr, err := db.EmailVerificationTokenRecord(verificationToken)
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.Equal(t, verificationToken, tr.Token)

	err = db.DisavowEmail(verificationToken)
	require.NoError(t, err)

	// make sure the token record is gone
	tr, err = db.EmailVerificationTokenRecord(verificationToken)
	require.NoError(t, err)
	require.Nil(t, tr)
}

func TestMessagesPart1(t *testing.T) {
	db := newDB(t)

	msgs, err := db.MessageRecords(3)
	require.NoError(t, err)
	require.Empty(t, msgs)

	expected := relstor.MessageRecord{
		RecipientID: 2,
		SenderID:    3,
		CipherText:  []byte("cipher-text"),
		Nonce:       []byte("nonce"),
		SentDate:    19495478,
	}

	expected.ID, err = db.InsertMessage(expected.RecipientID, expected.SenderID, expected.CipherText, expected.Nonce, expected.SentDate)
	require.NoError(t, err)
	require.Greater(t, expected.ID, int64(0))

	msgs, err = db.MessageRecords(expected.RecipientID)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	require.Equal(t, expected, msgs[0])
}

func TestMessagesPart2(t *testing.T) {
	db := newDB(t)

	actual, err := db.MessageToRecipient(3, 5)
	require.NoError(t, err)
	require.Nil(t, actual)

	expected := relstor.MessageRecord{
		RecipientID: 2,
		SenderID:    3,
		CipherText:  []byte("cipher-text"),
		Nonce:       []byte("nonce"),
		SentDate:    19495478,
	}

	expected.ID, err = db.InsertMessage(expected.RecipientID, expected.SenderID, expected.CipherText, expected.Nonce, expected.SentDate)
	require.NoError(t, err)
	require.Greater(t, expected.ID, int64(0))

	// wrong message id
	actual, err = db.MessageToRecipient(expected.RecipientID, 5000)
	require.NoError(t, err)
	require.Nil(t, actual)

	// wrong recipient
	actual, err = db.MessageToRecipient(5000, expected.ID)
	require.NoError(t, err)
	require.Nil(t, actual)

	actual, err = db.MessageToRecipient(expected.RecipientID, expected.ID)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, expected, *actual)

	// try deleting in various ways
	// wrong message id
	err = db.DeleteMessageToRecipient(expected.RecipientID, 5000)
	require.NoError(t, err)
	actual, _ = db.MessageToRecipient(expected.RecipientID, expected.ID)
	require.NotNil(t, actual, "Expcted the message to still exist after a bad delete call")
	require.Equal(t, expected, *actual, "expected the message to still match after a bad delete call")

	// wrong recipient id
	err = db.DeleteMessageToRecipient(5000, expected.ID)
	require.NoError(t, err)
	actual, _ = db.MessageToRecipient(expected.RecipientID, expected.ID)
	require.NotNil(t, actual, "Expcted the message to still exist after a bad delete call")
	require.Equal(t, expected, *actual, "expected the message to still match after a bad delete call")

	// proper deletion
	err = db.DeleteMessageToRecipient(expected.RecipientID, expected.ID)
	require.NoError(t, err)
	// the message should actually be gone now
	actual, err = db.MessageToRecipient(expected.RecipientID, expected.ID)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestInsertUser2(t *testing.T) {
	u := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "alice",
	}
	db := newDB(t)
	var err error
	u.ID, err = db.InsertUser(u, nil)
	require.NoError(t, err)
	require.Greater(t, u.ID, int64(0))

	// make sure a user with the same username can't be inserted
	_, err = db.InsertUser(u, nil)
	require.Equal(t, relstor.ErrDuplicateUsername, err)

	// make sure we retrieve the same user back
	actual, err := db.User(u.Username)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, u, *actual)

	// make sure searching for a non-existent user gives us an appropriate error
	actual, err = db.User("eve")
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestLimitedUserInfo(t *testing.T) {
	db := newDB(t)
	id, pubKey, err := db.LimitedUserInfo("invalid")
	require.NoError(t, err)
	require.Zero(t, id)
	require.Nil(t, pubKey)

	user := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "alice",
	}

	user.ID, err = db.InsertUser(user, nil)
	require.NoError(t, err)

	id, pubKey, err = db.LimitedUserInfo(user.Username)
	require.NoError(t, err)
	require.Equal(t, user.ID, id)
	require.Equal(t, user.PublicKey, pubKey)
}

func TestLimitedUserInfoID(t *testing.T) {
	db := newDB(t)
	username, pubKey, err := db.LimitedUserInfoID(1)
	require.NoError(t, err)
	require.Empty(t, username)
	require.Nil(t, pubKey)

	user := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "alice",
	}

	user.ID, err = db.InsertUser(user, nil)
	require.NoError(t, err)

	username, pubKey, err = db.LimitedUserInfoID(user.ID)
	require.NoError(t, err)
	require.Equal(t, user.Username, username)
	require.Equal(t, user.PublicKey, pubKey)
}

func TestUsername(t *testing.T) {
	db := newDB(t)
	actual := db.Username(33491)
	require.Empty(t, actual)

	user := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "alice",
	}
	var err error
	user.ID, err = db.InsertUser(user, nil)
	require.NoError(t, err)

	actual = db.Username(user.ID)
	require.Equal(t, user.Username, actual)
}

func TestUsernameAvailable(t *testing.T) {
	db := newDB(t)
	username := "alice"
	available, err := db.UsernameAvailable(username)
	require.NoError(t, err)
	require.True(t, available)

	user := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    username,
	}
	user.ID, err = db.InsertUser(user, nil)
	require.NoError(t, err)

	available, err = db.UsernameAvailable(username)
	require.NoError(t, err)
	require.False(t, available)
}

func TestUserPublicKey(t *testing.T) {
	db := newDB(t)
	actual, err := db.UserPublicKey(2)
	require.NoError(t, err)
	require.Nil(t, actual)

	user := relstor.UserRecord{
		PasswordHashAlgorithm:       "argon2id13",
		PasswordHashMemoryLimit:     32768,
		PasswordHashOperationsLimit: 6,
		PasswordSalt:                []byte("password-salt"),
		PublicKey:                   []byte("public-key"),
		WrappedSecretKey:            []byte("wrapped-secret-key"),
		WrappedSecretKeyNonce:       []byte("wrapped-secret-key-nonce"),
		WrappedSymmetricKey:         []byte("wrapped-symmetric-ket"),
		WrappedSymmetricKeyNonce:    []byte("wrapped-symmetric-key-nonce"),
		Username:                    "alice",
	}

	user.ID, err = db.InsertUser(user, nil)
	require.NoError(t, err)

	actual, err = db.UserPublicKey(user.ID)
	require.NoError(t, err)
	require.Equal(t, user.PublicKey, actual)
}

func TestSessionChallenge(t *testing.T) {
	db := newDB(t)

	expected := relstor.SessionChallengeRecord{
		Challenge:    []byte("challenge-all-the-things"),
		CreationDate: time.Now().Unix(),
		UserID:       32,
	}
	err := db.InsertSessionChallenge(expected.UserID, expected.CreationDate, expected.Challenge)
	require.NoError(t, err)

	actual, err := db.SessionChallenge(expected.UserID)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.NotZero(t, actual.ID)
	expected.ID = actual.ID
	require.Equal(t, expected, *actual)

	// delete it with a bad user id
	err = db.DeleteSessionChallengeUser(5000)
	require.NoError(t, err)
	// it should still be there
	actual, err = db.SessionChallenge(expected.UserID)
	require.NoError(t, err)
	require.Equal(t, expected, *actual)

	// delete it with the correct user id
	err = db.DeleteSessionChallengeUser(expected.UserID)
	require.NoError(t, err)
	// the challenge should not be there anymore
	actual, err = db.SessionChallenge(expected.UserID)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestDeleteSessionChallengeID(t *testing.T) {
	db := newDB(t)

	expected := relstor.SessionChallengeRecord{
		Challenge:    []byte("challenge-all-the-things"),
		CreationDate: time.Now().Unix(),
		UserID:       32,
	}
	err := db.InsertSessionChallenge(expected.UserID, expected.CreationDate, expected.Challenge)
	require.NoError(t, err)

	// delete it with a bad id
	err = db.DeleteSessionChallengeID(5000)
	require.NoError(t, err)
	// the challenge should still be there
	actual, err := db.SessionChallenge(expected.UserID)
	require.NoError(t, err)
	require.NotNil(t, actual)
	expected.ID = actual.ID
	require.Equal(t, expected, *actual)

	// delete it with the correct challenge id
	err = db.DeleteSessionChallengeID(expected.ID)
	require.NoError(t, err)
	// the challenge should be gone
	actual, err = db.SessionChallenge(expected.UserID)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestInsertAndGetFCMToken(t *testing.T) {
	db := newDB(t)

	userID := int64(14)
	fcmToken := "an-fcm-token-from-google"
	err := db.InsertFCMToken(userID, fcmToken)
	require.NoError(t, err)

	// try to retrieve it
	actual, err := db.FCMToken(fcmToken)
	require.NoError(t, err)
	require.Equal(t, userID, actual.UserID)
	require.Equal(t, fcmToken, actual.Token)
	require.NotZero(t, actual.ID)

	// provide a bad token
	actual, err = db.FCMToken("bad-token")
	require.NoError(t, err)
	require.Nil(t, actual)

	// try to receive another way
	actual, err = db.FCMTokenUser(userID, fcmToken)
	require.NoError(t, err)
	require.Equal(t, userID, actual.UserID)
	require.Equal(t, fcmToken, actual.Token)
	require.NotZero(t, actual.ID)

	// try with a bad token
	actual, err = db.FCMTokenUser(5000, "bad-token")
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestUpdateUserIDofFCMToken(t *testing.T) {
	db := newDB(t)
	oldUserID := int64(12)
	token := "the-fcm-token"
	err := db.InsertFCMToken(oldUserID, token)
	require.NoError(t, err)

	// the 'old user' has logged out of the phone, and a 'new user' has logged in, thus taking over the device's FCM token
	newUserID := int64(23)
	err = db.UpdateUserIDOfFCMToken(newUserID, token)
	require.NoError(t, err)

	// make sure we get the correct record
	actual, err := db.FCMToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.NotZero(t, actual.ID)
	require.Equal(t, newUserID, actual.UserID)
	require.Equal(t, token, actual.Token)
}

func TestReplaceFCMToken(t *testing.T) {
	db := newDB(t)
	userID := int64(31)
	oldToken := "old-token"
	err := db.InsertFCMToken(userID, oldToken)
	require.NoError(t, err)

	// update FCM token of a user
	newToken := "new-token"
	rowsAffected, err := db.ReplaceFCMToken(oldToken, newToken)
	require.NoError(t, err)
	require.EqualValues(t, 1, rowsAffected)

	// make sure we get the correct record
	actual, err := db.FCMToken(newToken)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.NotZero(t, actual.ID)
	require.Equal(t, userID, actual.UserID)
	require.Equal(t, newToken, actual.Token)
}

func TestDeleteFCMTokenOfUser(t *testing.T) {
	db := newDB(t)
	userID := int64(78)
	token := "fcm-token"
	err := db.InsertFCMToken(userID, token)
	require.NoError(t, err)

	// delete with a bad user id
	err = db.DeleteFCMTokenOfUser(5000, token)
	require.NoError(t, err)

	// make sure it's still there
	actual, err := db.FCMToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// delete with a bad token
	err = db.DeleteFCMTokenOfUser(userID, "bad-token")
	require.NoError(t, err)

	// make sure it's still there
	actual, err = db.FCMToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// delete with correct arguments
	err = db.DeleteFCMTokenOfUser(userID, token)
	require.NoError(t, err)

	// make sure it's not there
	actual, err = db.FCMToken(token)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestDeleteFCMToken(t *testing.T) {
	db := newDB(t)
	userID := int64(11)
	token := "fcm-token"

	err := db.InsertFCMToken(userID, token)
	require.NoError(t, err)

	// delete by specifying a bad token
	err = db.DeleteFCMToken("bad-token")
	require.NoError(t, err)

	// the token should still be there
	actual, err := db.FCMToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	err = db.DeleteFCMToken(token)
	require.NoError(t, err)

	// the token should be gone
	actual, err = db.FCMToken(token)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestFCMTokensRaw(t *testing.T) {
	// add a bunch of tokens for a new fictitious user
	db := newDB(t)
	numTokens := 8
	userID := int64(4)
	for i := 0; i < numTokens; i++ {
		err := db.InsertFCMToken(userID, fmt.Sprintf("token-deadbeef-%d", i))
		require.NoError(t, err)
	}

	tokens, err := db.FCMTokensRaw(userID)
	require.NoError(t, err)
	require.Len(t, tokens, numTokens)
}

func TestInsertAndGetAPNSToken(t *testing.T) {
	db := newDB(t)
	userID := int64(8)
	token := "apns-token"
	err := db.InsertAPNSToken(userID, token)
	require.NoError(t, err)

	// retrieve it
	actual, err := db.APNSToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.NotZero(t, actual.ID)
	require.Equal(t, userID, actual.UserID)
	require.Equal(t, token, actual.Token)

	// retrieve with a bad token argument
	actual, err = db.APNSToken("bad-token")
	require.NoError(t, err)
	require.Nil(t, actual)

	// retrieve it another way
	actual, err = db.APNSTokenUser(userID, token)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.NotZero(t, actual.ID)
	require.Equal(t, userID, actual.UserID)
	require.Equal(t, token, actual.Token)

	// retrieve it with a bad user id
	actual, err = db.APNSTokenUser(5000, token)
	require.NoError(t, err)
	require.Nil(t, actual)

	// retrieve it with a bad token
	actual, err = db.APNSTokenUser(userID, "bad-token")
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestUpdateUserIDOfAPNSToken(t *testing.T) {
	// the old user has logged out of their phone, and the new user has logged in, thus taking over the device's FCM token
	db := newDB(t)

	oldUserID := int64(6)
	token := "apns-token"
	err := db.InsertAPNSToken(oldUserID, token)
	require.NoError(t, err)

	newUserID := int64(9)
	err = db.UpdateUserIDOfAPNSToken(newUserID, token)
	require.NoError(t, err)

	actual, err := db.APNSToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, newUserID, actual.UserID)
	require.Equal(t, token, actual.Token)
}

func TestReplaceAPNSToken(t *testing.T) {
	db := newDB(t)

	oldToken := "old-apns-token"
	userID := int64(12)
	err := db.InsertAPNSToken(userID, oldToken)
	require.NoError(t, err)

	// the APNS token has been updated on the device
	newToken := "new-apns-token"
	rowsAffected, err := db.ReplaceAPNSToken(oldToken, newToken)
	require.NoError(t, err)
	require.EqualValues(t, 1, rowsAffected)

	// make sure we get the correct record
	actual, err := db.APNSToken(newToken)
	require.NoError(t, err)
	require.NotNil(t, actual)
	require.Equal(t, newToken, actual.Token)
	require.Equal(t, userID, actual.UserID)
}

func TestDeleteAPNSTokensOfUser(t *testing.T) {
	db := newDB(t)

	userID := int64(4)
	token := "apns-token"
	err := db.InsertAPNSToken(userID, token)
	require.NoError(t, err)

	// delete with a bad user id
	err = db.DeleteAPNSTokenOfUser(5000, token)
	require.NoError(t, err)

	// make sure it's still there
	actual, err := db.APNSToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// delete with a bad token
	err = db.DeleteAPNSTokenOfUser(userID, "bad-token")
	require.NoError(t, err)

	// make sure it's still there
	actual, err = db.APNSToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// delete with good arguments
	err = db.DeleteAPNSTokenOfUser(userID, token)
	require.NoError(t, err)

	// make sure it's gone
	actual, err = db.APNSToken(token)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestDeleteAPNSToken(t *testing.T) {
	db := newDB(t)

	userID := int64(2)
	token := "apns-token"
	err := db.InsertAPNSToken(userID, token)
	require.NoError(t, err)

	// delete with a bad token
	err = db.DeleteAPNSToken("bad-token")
	require.NoError(t, err)

	// make sure it's still there
	actual, err := db.APNSToken(token)
	require.NoError(t, err)
	require.NotNil(t, actual)

	// delete it properly
	err = db.DeleteAPNSToken(token)
	require.NoError(t, err)

	// make sure it's gone
	actual, err = db.APNSToken(token)
	require.NoError(t, err)
	require.Nil(t, actual)
}

func TestAPNSTokensRaw(t *testing.T) {
	db := newDB(t)

	tokens, err := db.APNSTokensRaw(100)
	require.NoError(t, err)
	require.Empty(t, tokens)

	// add a bunch of tokens for a new fictitious user
	numTokens := 8
	var userID int64 = 100
	for i := 0; i < numTokens; i++ {
		err := db.InsertAPNSToken(userID, fmt.Sprintf("token-livebeef-%d", i))
		require.NoError(t, err)
	}

	tokens, err = db.APNSTokensRaw(userID)
	require.NoError(t, err)
	require.Len(t, tokens, numTokens)
}

func TestTickets(t *testing.T) {
	db := newDB(t)

	// make sure we don't get a ticket from an empty db
	userID, timestamp, err := db.Ticket("deadbeef")
	require.NoError(t, err)
	require.Zero(t, userID)
	require.Zero(t, timestamp)

	ticket := "boppity-bop"
	var expectedID int64 = 42
	err = db.InsertTicket(ticket, expectedID)
	require.NoError(t, err)

	userID, timestamp, err = db.Ticket(ticket)
	require.NoError(t, err)
	require.Equal(t, expectedID, userID)
	// the timestamp shouldn't be older than 1 second ago
	now := time.Now().Unix()
	require.Greater(t, timestamp, now-1)
	// the timestamp shouldn't be in the future either
	require.LessOrEqual(t, timestamp, now)

	// test ticket deletion
	err = db.DeleteTickets(now - 5)
	require.NoError(t, err)

	// the ticket should still be in the database
	userID, _, err = db.Ticket(ticket)
	require.NoError(t, err)
	require.Equal(t, expectedID, userID)

	// perform a delete that SHOULD delete our ticket
	err = db.DeleteTickets(now)
	require.NoError(t, err)

	// make sure the ticket no longer exists
	userID, timestamp, err = db.Ticket(ticket)
	require.NoError(t, err)
	require.Zero(t, userID)
	require.Zero(t, timestamp)
}
