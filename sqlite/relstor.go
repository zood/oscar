package sqlite

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3" // because, duh
	"github.com/pkg/errors"
	"zood.xyz/oscar/relstor"
)

// InMemoryDSN creates a temporary in-memory only database when used as a DSN
const InMemoryDSN = ":memory:"

type sqliteDB struct {
	dbx *sqlx.DB
}

// New returns a relstor.Provider backed by sqlite
func New(dsn string) (relstor.Provider, error) {
	dbx, err := sqlx.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	dbx.SetMaxOpenConns(1)

	db := sqliteDB{dbx: dbx}
	// check db version
	ver := db.schemaVersion()
	tx, err := db.dbx.Beginx()
	if err != nil {
		return nil, errors.Wrap(err, "unable to begin transaction for database migration")
	}
	defer tx.Rollback()
	switch ver {
	case 0:
		for _, q := range migrationQueries001 {
			_, err := tx.Exec(q)
			if err != nil {
				return nil, err
			}
		}
		fallthrough
	case 1:
		// database schema is up to date. nothing to do.
	}
	db.setSchemaVersion(tx, 1)

	err = tx.Commit()
	if err != nil {
		return nil, errors.Wrap(err, "error committing migration transaction")
	}

	return db, nil
}

func (db sqliteDB) APNSToken(token string) (*relstor.APNSTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_apns_tokens WHERE token=?`
	ftr := relstor.APNSTokenRecord{Token: token}
	err := db.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) APNSTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_apns_tokens WHERE user_id=?`
	tokens := make([]string, 0)
	err := db.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) APNSTokenUser(userID int64, token string) (*relstor.APNSTokenRecord, error) {
	const query = "SELECT id FROM user_apns_tokens WHERE user_id=? AND token=?"
	var id int64
	err := db.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.APNSTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) DeleteAPNSToken(token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE token=?`
	_, err := db.dbx.Exec(query, token)
	return err
}

func (db sqliteDB) DeleteAPNSTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE user_id=? AND token=?`
	_, err := db.dbx.Exec(query, userID, token)
	return err
}

func (db sqliteDB) DeleteFCMToken(token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE token=?`
	_, err := db.dbx.Exec(query, token)
	return err
}

func (db sqliteDB) DeleteFCMTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE user_id=? AND token=?`
	_, err := db.dbx.Exec(query, userID, token)
	return err
}

func (db sqliteDB) DeleteMessageToRecipient(recipientID, msgID int64) error {
	deleteSQL := `DELETE FROM messages WHERE recipient_id=? AND id=?`
	_, err := db.dbx.Exec(deleteSQL, recipientID, msgID)
	if err != nil {
		return errors.Wrap(err, "unable to execute message deletion")
	}

	return nil
}

func (db sqliteDB) DeleteSessionChallengeID(id int64) error {
	_, err := db.dbx.Exec("DELETE FROM session_challenges WHERE id=?", id)
	return err
}

func (db sqliteDB) DeleteSessionChallengeUser(userID int64) error {
	_, err := db.dbx.Exec("DELETE FROM session_challenges WHERE user_id=?", userID)
	return err
}

func (db sqliteDB) DisavowEmail(token string) error {
	const query = `DELETE FROM email_verification_tokens WHERE token=?`
	_, err := db.dbx.Exec(query, token)
	if err != nil {
		return errors.Wrap(err, "unable to execute query")
	}

	return nil
}

func (db sqliteDB) EmailVerificationTokenRecord(token string) (*relstor.EmailVerificationTokenRecord, error) {
	const query = `SELECT user_id, email, send_date FROM email_verification_tokens WHERE token=?`
	evtr := relstor.EmailVerificationTokenRecord{}
	err := db.dbx.QueryRow(query, token).Scan(&evtr.UserID, &evtr.Email, &evtr.SendDate)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}

	evtr.Token = token

	return &evtr, nil
}

func (db sqliteDB) FCMToken(token string) (*relstor.FCMTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_fcm_tokens WHERE token=?`
	ftr := relstor.FCMTokenRecord{Token: token}
	err := db.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) FCMTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_fcm_tokens WHERE user_id=?`
	tokens := make([]string, 0)
	err := db.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) FCMTokenUser(userID int64, token string) (*relstor.FCMTokenRecord, error) {
	const query = "SELECT id FROM user_fcm_tokens WHERE user_id=? AND token=?"
	var id int64
	err := db.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.FCMTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) InsertAPNSToken(userID int64, token string) error {
	const query = `INSERT INTO user_apns_tokens (user_id, token) VALUES (?, ?)`
	_, err := db.dbx.Exec(query, userID, token)
	return err
}

func (db sqliteDB) InsertFCMToken(userID int64, token string) error {
	const query = `INSERT INTO user_fcm_tokens (user_id, token) VALUES (?, ?)`
	_, err := db.dbx.Exec(query, userID, token)
	return err
}

func (db sqliteDB) InsertMessage(recipientID, senderID int64, cipherText, nonce []byte, sentDate int64) (int64, error) {
	insertSQL := `
	INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
	result, err := db.dbx.Exec(insertSQL, recipientID, senderID, cipherText, nonce, sentDate)
	if err != nil {
		return 0, errors.Wrap(err, "SQL insert exec failed")
	}
	msgID, err := result.LastInsertId()
	if err != nil {
		return 0, errors.Wrap(err, "unable to retrieve id of newly created message record")
	}

	return msgID, nil
}

func (db sqliteDB) InsertSessionChallenge(userID int64, creationDate int64, challenge []byte) error {
	insertSQL := `
	INSERT INTO session_challenges (user_id, creation_date, challenge) VALUES (?, ?, ?)`
	_, err := db.dbx.Exec(insertSQL, userID, creationDate, challenge)
	if err != nil {
		return errors.Wrap(err, "Unable to insert session challenge")
	}

	return nil
}

func (db sqliteDB) InsertUser(user relstor.UserRecord, verificationToken *string) (int64, error) {
	// we don't insert the email, because it only gets inserted upon verification
	insertSQL := `
	INSERT INTO users (	username,
						password_salt,
						password_hash_algorithm,
						password_hash_operations_limit,
						password_hash_memory_limit,
		 				public_key,
						wrapped_secret_key,
						wrapped_secret_key_nonce,
						wrapped_symmetric_key,
						wrapped_symmetric_key_nonce)
						VALUES (:username,
								:password_salt,
								:password_hash_algorithm,
								:password_hash_operations_limit,
								:password_hash_memory_limit,
								:public_key,
								:wrapped_secret_key,
								:wrapped_secret_key_nonce,
								:wrapped_symmetric_key,
								:wrapped_symmetric_key_nonce)`
	tx, err := db.dbx.Beginx()
	if err != nil {
		return 0, errors.Wrap(err, "unable to start transaction")
	}
	defer tx.Rollback()

	result, err := tx.NamedExec(insertSQL, user)
	if err != nil {
		return 0, errors.Wrap(err, "failed to insert user into table")
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return 0, errors.Wrap(err, "unable to obtain id of new user record")
	}

	// if there is a verification token, create a record for that as well
	if verificationToken != nil && user.Email != nil {
		insertSQL = `INSERT INTO email_verification_tokens (user_id, token, email, send_date) VALUES (?, ?, ?, ?)`
		_, err = tx.Exec(insertSQL, userID, *verificationToken, user.Email, time.Now().Unix())
		if err != nil {
			return 0, errors.Wrap(err, "unable to insert verification token")
		}
	}

	err = tx.Commit()
	if err != nil {
		return 0, errors.Wrap(err, "unable to commit InsertUser")
	}

	return userID, nil
}

func (db sqliteDB) LimitedUserInfo(username string) (id int64, pubKey []byte, err error) {
	err = db.dbx.QueryRow("SELECT id, public_key FROM users WHERE username=?", username).Scan(&id, &pubKey)
	switch err {
	case nil:
		return id, pubKey, nil
	case sql.ErrNoRows:
		return 0, nil, nil
	default:
		return 0, nil, err
	}
}

func (db sqliteDB) LimitedUserInfoID(userID int64) (username string, pubKey []byte, err error) {
	err = db.dbx.QueryRow("SELECT username, public_key FROM users WHERE id=?", userID).Scan(&username, &pubKey)
	switch err {
	case nil:
		return username, pubKey, nil
	case sql.ErrNoRows:
		return "", nil, nil
	default:
		return "", nil, err
	}
}

func (db sqliteDB) MessageRecords(recipientID int64) ([]relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=?`
	rows, err := db.dbx.Queryx(selectSQL, recipientID)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute select on messages table")
	}
	defer rows.Close()

	msgs := make([]relstor.MessageRecord, 0, 0)
	for rows.Next() {
		msg := relstor.MessageRecord{}
		err = rows.StructScan(&msg)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan a row")
		}
		msgs = append(msgs, msg)
	}

	return msgs, nil
}

func (db sqliteDB) schemaVersion() int {
	var v int
	err := db.dbx.QueryRow("PRAGMA user_version;").Scan(&v)
	if err != nil {
		log.Printf("There is no reason 'PRAMGA user_version' should fail: %v", err)
		panic(err)
	}
	return v
}

func (db sqliteDB) setSchemaVersion(tx *sqlx.Tx, version int) error {
	query := fmt.Sprintf("PRAGMA user_version = %d", version)
	_, err := tx.Exec(query)
	return err
}

func (db sqliteDB) MessageToRecipient(recipientID, msgID int64) (*relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=? AND id=?`
	msg := relstor.MessageRecord{}
	err := db.dbx.Get(&msg, selectSQL, recipientID, msgID)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "selecting message failed")
	}

	return &msg, nil
}

func (db sqliteDB) ReplaceAPNSToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_apns_tokens SET token=? WHERE token=?`
	var result sql.Result
	result, err = db.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (db sqliteDB) ReplaceFCMToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_fcm_tokens SET token=? WHERE token=?`
	var result sql.Result
	result, err = db.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (db sqliteDB) SessionChallenge(userID int64) (*relstor.SessionChallengeRecord, error) {
	const challengeSQL = `
	SELECT id, creation_date, challenge FROM session_challenges WHERE user_id=?`
	var challenge relstor.SessionChallengeRecord
	err := db.dbx.QueryRowx(challengeSQL, userID).StructScan(&challenge)
	switch err {
	case nil:
		challenge.UserID = userID
		return &challenge, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "Unable to query for session challenge")
	}
}

func (db sqliteDB) UpdateUserIDOfAPNSToken(newUserID int64, token string) error {
	const query = `UPDATE user_apns_tokens SET user_id=? WHERE token=?`
	_, err := db.dbx.Exec(query, newUserID, token)
	return err
}

func (db sqliteDB) UpdateUserIDOfFCMToken(newUserID int64, token string) error {
	const query = `UPDATE user_fcm_tokens SET user_id=? WHERE token=?`
	_, err := db.dbx.Exec(query, newUserID, token)
	return err
}

func (db sqliteDB) User(username string) (*relstor.UserRecord, error) {
	query := `
	SELECT 	id,
			username,
			public_key,
			wrapped_secret_key,
			wrapped_secret_key_nonce,
			wrapped_symmetric_key,
			wrapped_symmetric_key_nonce,
			password_salt,
			password_hash_algorithm,
			password_hash_operations_limit,
			password_hash_memory_limit,
			email
	FROM users WHERE username=?`
	user := relstor.UserRecord{}
	err := db.dbx.Get(&user, query, username)
	switch err {
	case nil:
		return &user, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (db sqliteDB) Username(userID int64) string {
	var username sql.NullString
	err := db.dbx.QueryRow("SELECT username FROM users WHERE id=?", userID).Scan(&username)
	if err != nil {
		return ""
	}
	return username.String
}

func (db sqliteDB) UsernameAvailable(username string) (bool, error) {
	checkUsernameSQL := "SELECT id FROM users WHERE username=?"
	var foundID int
	err := db.dbx.QueryRow(checkUsernameSQL, username).Scan(&foundID)
	switch err {
	case nil:
		return false, nil
	case sql.ErrNoRows:
		return true, nil
	default:
		return false, errors.Wrap(err, "error checking if username is available")
	}
}

func (db sqliteDB) UserPublicKey(userID int64) ([]byte, error) {
	selectSQL := `SELECT public_key FROM users WHERE id=?`
	var pubKey []byte
	err := db.dbx.QueryRow(selectSQL, userID).Scan(&pubKey)
	switch err {
	case nil:
		return pubKey, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "unable to select user's public key")
	}
}

func (db sqliteDB) VerifyEmail(email string, userID int64) error {
	tx, err := db.dbx.Begin()
	if err != nil {
		return errors.Wrap(err, "unable to start a transaction")
	}
	defer tx.Rollback()

	_, err = tx.Exec(`UPDATE users SET email=? WHERE id=?`, email, userID)
	if err != nil {
		return errors.Wrap(err, "unable to update users table")
	}
	_, err = tx.Exec(`DELETE FROM email_verification_tokens WHERE user_id=?`, userID)
	if err != nil {
		return errors.Wrap(err, "unable to delete verification token from table")
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}

	return nil
}
