package cockroachdb

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"zood.xyz/oscar/relstor"
)

const (
	tableEmailVerificationTokens string = "email_verification_tokens"
	tableMessages                       = "messages"
	tableSessionChallenges              = "session_challenges"
	tableUserFCMTokens                  = "user_fcm_tokens"
	tableUsers                          = "users"
)

// provider is an implementation of the relstor.provider backed by cockroachdb
type provider struct {
	dbx *sqlx.DB
}

// New returns a relstor.Provider backed by a cockroach db instance
func New(connURI, dbName string) (relstor.Provider, error) {
	if connURI == "" {
		return nil, errors.New("Connection string is empty")
	}
	sqldb, err := sql.Open("postgres", connURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open CockroachDB")
	}
	err = sqldb.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "failed to ping cockroach db")
	}

	sqlxdb := sqlx.NewDb(sqldb, "postgres")

	_, err = sqlxdb.Exec(fmt.Sprintf("SET database = %s", dbName))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set database")
	}

	return provider{dbx: sqlxdb}, nil
}

func (cdb provider) APNSToken(token string) (*relstor.APNSTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_apns_tokens WHERE token=$1`
	ftr := relstor.APNSTokenRecord{Token: token}
	err := cdb.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (cdb provider) APNSTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_apns_tokens WHERE user_id=$1`
	tokens := make([]string, 0)
	err := cdb.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (cdb provider) APNSTokenUser(userID int64, token string) (*relstor.APNSTokenRecord, error) {
	const query = "SELECT id FROM user_apns_tokens WHERE user_id=$1 AND token=$2"
	var id int64
	err := cdb.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.APNSTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (cdb provider) DeleteAPNSToken(token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE token=$1`
	_, err := cdb.dbx.Exec(query, token)
	return err
}

func (cdb provider) DeleteAPNSTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE user_id=$1 AND token=$2`
	_, err := cdb.dbx.Exec(query, userID, token)
	return err
}

func (cdb provider) DeleteFCMToken(token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE token=$1`
	_, err := cdb.dbx.Exec(query, token)
	return err
}

func (cdb provider) DeleteFCMTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE user_id=$1 AND token=$2`
	_, err := cdb.dbx.Exec(query, userID, token)
	return err
}

func (cdb provider) DeleteMessageToRecipient(recipientID, msgID int64) error {
	deleteSQL := `DELETE FROM messages WHERE recipient_id=$1 AND id=$2`
	_, err := cdb.dbx.Exec(deleteSQL, recipientID, msgID)
	if err != nil {
		return errors.Wrap(err, "unable to execute message deletion")
	}

	return nil
}

func (cdb provider) DeleteSessionChallengeID(id int64) error {
	_, err := cdb.dbx.Exec("DELETE FROM session_challenges WHERE id=$1", id)
	return err
}

func (cdb provider) DeleteSessionChallengeUser(userID int64) error {
	_, err := cdb.dbx.Exec("DELETE FROM session_challenges WHERE user_id=$1", userID)
	return err
}

func (cdb provider) DisavowEmail(token string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE token=$1", tableEmailVerificationTokens)
	_, err := cdb.dbx.Exec(query, token)
	if err != nil {
		return errors.Wrap(err, "unable to execute query")
	}

	return nil
}

func (cdb provider) EmailVerificationTokenRecord(token string) (*relstor.EmailVerificationTokenRecord, error) {
	query := fmt.Sprintf(`SELECT user_id, email, send_date FROM %s WHERE token=$1`, tableEmailVerificationTokens)
	evtr := relstor.EmailVerificationTokenRecord{}
	err := cdb.dbx.QueryRow(query, token).Scan(&evtr.UserID, &evtr.Email, &evtr.SendDate)
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

func (cdb provider) FCMToken(token string) (*relstor.FCMTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_fcm_tokens WHERE token=$1`
	ftr := relstor.FCMTokenRecord{Token: token}
	err := cdb.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (cdb provider) FCMTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_fcm_tokens WHERE user_id=$1`
	tokens := make([]string, 0)
	err := cdb.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (cdb provider) FCMTokenUser(userID int64, token string) (*relstor.FCMTokenRecord, error) {
	const query = "SELECT id FROM user_fcm_tokens WHERE user_id=$1 AND token=$2"
	var id int64
	err := cdb.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.FCMTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (cdb provider) InsertAPNSToken(userID int64, token string) error {
	const query = `INSERT INTO user_apns_tokens (user_id, token) VALUES ($1, $2)`
	_, err := cdb.dbx.Exec(query, userID, token)
	return err
}

func (cdb provider) InsertFCMToken(userID int64, token string) error {
	const query = `INSERT INTO user_fcm_tokens (user_id, token) VALUES ($1, $2)`
	_, err := cdb.dbx.Exec(query, userID, token)
	return err
}

func (cdb provider) InsertMessage(recipientID, senderID int64, cipherText, nonce []byte, sentDate int64) (int64, error) {
	insertSQL := `
	INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES ($1, $2, $3, $4, $5) RETURNING id`
	var msgID int64
	err := cdb.dbx.QueryRow(insertSQL, recipientID, senderID, cipherText, nonce, sentDate).Scan(&msgID)
	if err != nil {
		return 0, errors.Wrap(err, "SQL insert exec failed")
	}

	return msgID, nil
}

func (cdb provider) InsertSessionChallenge(userID int64, creationDate int64, challenge []byte) error {
	insertSQL := `
	INSERT INTO session_challenges (user_id, creation_date, challenge) VALUES ($1, $2, $3)`
	_, err := cdb.dbx.Exec(insertSQL, userID, creationDate, challenge)
	if err != nil {
		return errors.Wrap(err, "Unable to insert session challenge")
	}

	return nil
}

func (cdb provider) InsertUser(user relstor.UserRecord, verificationToken *string) (int64, error) {
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
								:wrapped_symmetric_key_nonce) RETURNING id;`
	tx, err := cdb.dbx.Beginx()
	if err != nil {
		return 0, errors.Wrap(err, "unable to start transaction")
	}
	defer tx.Rollback()

	rows, err := tx.NamedQuery(insertSQL, user)
	if err != nil {
		return 0, errors.Wrap(err, "failed to insert user into table")
	}
	defer rows.Close()
	var userID int64
	if rows.Next() {
		err = rows.Scan(&userID)
		if err != nil {
			return 0, errors.Wrap(err, "unable to obtain id of new user record")
		}
	} else {
		return 0, errors.New("failed to iterate rows to get user id")
	}

	rows.Close()

	// if there is a verification token, create a record for that as well
	if verificationToken != nil && user.Email != nil {
		insertSQL = `INSERT INTO email_verification_tokens (user_id, token, email, send_date) VALUES ($1, $2, $3, $4)`
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

func (cdb provider) LimitedUserInfo(username string) (id int64, pubKey []byte, err error) {
	err = cdb.dbx.QueryRow("SELECT id, public_key FROM users WHERE username=$1", username).Scan(&id, &pubKey)
	switch err {
	case nil:
		return id, pubKey, nil
	case sql.ErrNoRows:
		return 0, nil, nil
	default:
		return 0, nil, err
	}
}

func (cdb provider) LimitedUserInfoID(userID int64) (username string, pubKey []byte, err error) {
	err = cdb.dbx.QueryRow("SELECT username, public_key FROM users WHERE id=$1", userID).Scan(&username, &pubKey)
	switch err {
	case nil:
		return username, pubKey, nil
	case sql.ErrNoRows:
		return "", nil, nil
	default:
		return "", nil, err
	}
}

func (cdb provider) MessageRecords(recipientID int64) ([]relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=$1`
	rows, err := cdb.dbx.Queryx(selectSQL, recipientID)
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

func (cdb provider) MessageToRecipient(recipientID, msgID int64) (*relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=$1 AND id=$2`
	msg := relstor.MessageRecord{}
	err := cdb.dbx.Get(&msg, selectSQL, recipientID, msgID)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "selecting message failed")
	}

	return &msg, nil
}

func (cdb provider) ReplaceAPNSToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_apns_tokens SET token=$1 WHERE token=$2`
	var result sql.Result
	result, err = cdb.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (cdb provider) ReplaceFCMToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_fcm_tokens SET token=$1 WHERE token=$2`
	var result sql.Result
	result, err = cdb.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (cdb provider) SessionChallenge(userID int64) (*relstor.SessionChallengeRecord, error) {
	const challengeSQL = `
	SELECT id, creation_date, challenge FROM session_challenges WHERE user_id=$1`
	var challenge relstor.SessionChallengeRecord
	err := cdb.dbx.QueryRowx(challengeSQL, userID).StructScan(&challenge)
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

func (cdb provider) UpdateUserIDOfAPNSToken(newUserID int64, token string) error {
	const query = `UPDATE user_apns_tokens SET user_id=$1 WHERE token=$2`
	_, err := cdb.dbx.Exec(query, newUserID, token)
	return err
}

func (cdb provider) UpdateUserIDOfFCMToken(newUserID int64, token string) error {
	const query = `UPDATE user_fcm_tokens SET user_id=$1 WHERE token=$2`
	_, err := cdb.dbx.Exec(query, newUserID, token)
	return err
}

func (cdb provider) User(username string) (*relstor.UserRecord, error) {
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
	FROM users WHERE username=$1`
	user := relstor.UserRecord{}
	err := cdb.dbx.Get(&user, query, username)
	switch err {
	case nil:
		return &user, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (cdb provider) Username(userID int64) string {
	var username sql.NullString
	err := cdb.dbx.QueryRow("SELECT username FROM users WHERE id=$1", userID).Scan(&username)
	if err != nil {
		return ""
	}
	return username.String
}

func (cdb provider) UsernameAvailable(username string) (bool, error) {
	checkUsernameSQL := "SELECT id FROM users WHERE username=$1"
	var foundID int
	err := cdb.dbx.QueryRow(checkUsernameSQL, username).Scan(&foundID)
	switch err {
	case nil:
		return false, nil
	case sql.ErrNoRows:
		return true, nil
	default:
		return false, errors.Wrap(err, "error checking if username is available")
	}
}

func (cdb provider) UserPublicKey(userID int64) ([]byte, error) {
	selectSQL := `SELECT public_key FROM users WHERE id=$1`
	var pubKey []byte
	err := cdb.dbx.QueryRow(selectSQL, userID).Scan(&pubKey)
	switch err {
	case nil:
		return pubKey, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "unable to select user's public key")
	}
}

func (cdb provider) VerifyEmail(email string, userID int64) error {
	tx, err := cdb.dbx.Begin()
	if err != nil {
		return errors.Wrap(err, "unable to start a transaction")
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE users SET email=$1 WHERE id=$2", email, userID)
	if err != nil {
		return errors.Wrap(err, "unable to update users table")
	}
	_, err = tx.Exec("DELETE FROM "+tableEmailVerificationTokens+" WHERE user_id=$1", userID)
	if err != nil {
		return errors.Wrap(err, "unable to delete verification token from table")
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}

	return nil
}
