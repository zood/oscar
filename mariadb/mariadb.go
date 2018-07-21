package mariadb

import (
	"database/sql"
	"fmt"
	"time"

	"pijun.io/oscar/relstor"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

const (
	tableEmailVerificationTokens string = "email_verification_tokens"
	tableMessages                       = "messages"
	tableSessionChallenges              = "session_challenges"
	tableUserAPNSTokens                 = "user_apns_tokens"
	tableUserFCMTokens                  = "user_fcm_tokens"
	tableUsers                          = "users"
)

// New creates a provider backed by a MariaDB instance
func New(sqlDSN string) (relstor.Provider, error) {
	if sqlDSN == "" {
		return nil, errors.New("sql dsn is empty")
	}
	sqldb, err := sql.Open("mysql", sqlDSN)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open MariaDB")
	}
	err = sqldb.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "failed to ping database")
	}
	sqldb.SetMaxOpenConns(100)
	sqldb.SetMaxIdleConns(30)

	sqlxdb := sqlx.NewDb(sqldb, "mysql")

	provider := mariaDBProvider{db: sqldb, dbx: sqlxdb}

	return provider, nil
}

type mariaDBProvider struct {
	db  *sql.DB
	dbx *sqlx.DB
}

func (mdp mariaDBProvider) APNSToken(token string) (*relstor.APNSTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_apns_tokens WHERE token=?`
	ftr := relstor.APNSTokenRecord{Token: token}
	err := mdp.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) APNSTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_apns_tokens WHERE user_id=?`
	tokens := make([]string, 0)
	err := mdp.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) APNSTokenUser(userID int64, token string) (*relstor.APNSTokenRecord, error) {
	const query = "SELECT id FROM user_apns_tokens WHERE user_id=? AND token=?"
	var id int64
	err := mdp.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.APNSTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) DeleteAPNSToken(token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE token=?`
	_, err := mdp.dbx.Exec(query, token)
	return err
}

func (mdp mariaDBProvider) DeleteAPNSTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_apns_tokens WHERE user_id=? AND token=?`
	_, err := mdp.dbx.Exec(query, userID, token)
	return err
}

func (mdp mariaDBProvider) DeleteFCMToken(token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE token=?`
	_, err := mdp.dbx.Exec(query, token)
	return err
}

func (mdp mariaDBProvider) DeleteFCMTokenOfUser(userID int64, token string) error {
	const query = `DELETE FROM user_fcm_tokens WHERE user_id=? AND token=?`
	_, err := mdp.dbx.Exec(query, userID, token)
	return err
}

func (mdp mariaDBProvider) DeleteMessageToRecipient(recipientID, msgID int64) error {
	deleteSQL := `DELETE FROM messages WHERE recipient_id=? AND id=?`
	_, err := mdp.dbx.Exec(deleteSQL, recipientID, msgID)
	if err != nil {
		return errors.Wrap(err, "unable to execute message deletion")
	}

	return nil
}

func (mdp mariaDBProvider) DeleteSessionChallengeID(id int64) error {
	_, err := mdp.dbx.Exec("DELETE FROM session_challenges WHERE id=?", id)
	return err
}

func (mdp mariaDBProvider) DeleteSessionChallengeUser(userID int64) error {
	_, err := mdp.dbx.Exec("DELETE FROM session_challenges WHERE user_id=?", userID)
	return err
}

func (mdp mariaDBProvider) DisavowEmail(token string) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE token=?", tableEmailVerificationTokens)
	_, err := mdp.db.Exec(query, token)
	if err != nil {
		return errors.Wrap(err, "unable to execute query")
	}

	return nil
}

func (mdp mariaDBProvider) EmailVerificationTokenRecord(token string) (*relstor.EmailVerificationTokenRecord, error) {
	query := fmt.Sprintf(`SELECT user_id, email, send_date FROM %s WHERE token=?`, tableEmailVerificationTokens)
	evtr := relstor.EmailVerificationTokenRecord{}
	err := mdp.dbx.QueryRow(query, token).Scan(&evtr.UserID, &evtr.Email, &evtr.SendDate)
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

func (mdp mariaDBProvider) FCMToken(token string) (*relstor.FCMTokenRecord, error) {
	const query = `SELECT id, user_id FROM user_fcm_tokens WHERE token=?`
	ftr := relstor.FCMTokenRecord{Token: token}
	err := mdp.dbx.QueryRowx(query, token).StructScan(&ftr)
	switch err {
	case nil:
		return &ftr, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) FCMTokensRaw(userID int64) ([]string, error) {
	const query = `SELECT token FROM user_fcm_tokens WHERE user_id=?`
	tokens := make([]string, 0)
	err := mdp.dbx.Select(&tokens, query, userID)
	switch err {
	case nil:
		fallthrough
	case sql.ErrNoRows:
		return tokens, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) FCMTokenUser(userID int64, token string) (*relstor.FCMTokenRecord, error) {
	const query = "SELECT id FROM user_fcm_tokens WHERE user_id=? AND token=?"
	var id int64
	err := mdp.dbx.QueryRow(query, userID, token).Scan(&id)
	switch err {
	case nil:
		return &relstor.FCMTokenRecord{ID: id, UserID: userID, Token: token}, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) InsertAPNSToken(userID int64, token string) error {
	const query = `INSERT INTO user_apns_tokens (user_id, token) VALUES (?, ?)`
	_, err := mdp.dbx.Exec(query, userID, token)
	return err
}

func (mdp mariaDBProvider) InsertFCMToken(userID int64, token string) error {
	const query = `INSERT INTO user_fcm_tokens (user_id, token) VALUES (?, ?)`
	_, err := mdp.dbx.Exec(query, userID, token)
	return err
}

func (mdp mariaDBProvider) InsertMessage(recipientID, senderID int64, cipherText, nonce []byte, sentDate int64) (int64, error) {
	insertSQL := `
	INSERT INTO messages (recipient_id, sender_id, cipher_text, nonce, sent_date) VALUES (?, ?, ?, ?, ?)`
	result, err := mdp.dbx.Exec(insertSQL, recipientID, senderID, cipherText, nonce, sentDate)
	if err != nil {
		return 0, errors.Wrap(err, "SQL insert exec failed")
	}
	msgID, err := result.LastInsertId()
	if err != nil {
		return 0, errors.Wrap(err, "unable to retrieve id of newly created message record")
	}

	return msgID, nil
}

func (mdp mariaDBProvider) InsertSessionChallenge(userID int64, creationDate int64, challenge []byte) error {
	insertSQL := `
	INSERT INTO session_challenges (user_id, creation_date, challenge) VALUES (?, ?, ?)`
	_, err := mdp.dbx.Exec(insertSQL, userID, creationDate, challenge)
	if err != nil {
		return errors.Wrap(err, "Unable to insert session challenge")
	}

	return nil
}

func (mdp mariaDBProvider) InsertUser(user relstor.UserRecord, verificationToken *string) (int64, error) {
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
	tx, err := mdp.dbx.Beginx()
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

func (mdp mariaDBProvider) LimitedUserInfo(username string) (id int64, pubKey []byte, err error) {
	err = mdp.dbx.QueryRow("SELECT id, public_key FROM users WHERE username=?", username).Scan(&id, &pubKey)
	switch err {
	case nil:
		return id, pubKey, nil
	case sql.ErrNoRows:
		return 0, nil, nil
	default:
		return 0, nil, err
	}
}

func (mdp mariaDBProvider) LimitedUserInfoID(userID int64) (username string, pubKey []byte, err error) {
	err = mdp.dbx.QueryRow("SELECT username, public_key FROM users WHERE id=?", userID).Scan(&username, &pubKey)
	switch err {
	case nil:
		return username, pubKey, nil
	case sql.ErrNoRows:
		return "", nil, nil
	default:
		return "", nil, err
	}
}

func (mdp mariaDBProvider) MessageRecords(recipientID int64) ([]relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=?`
	rows, err := mdp.dbx.Queryx(selectSQL, recipientID)
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

func (mdp mariaDBProvider) MessageToRecipient(recipientID, msgID int64) (*relstor.MessageRecord, error) {
	selectSQL := `
	SELECT id, recipient_id, sender_id, cipher_text, nonce, sent_date FROM messages WHERE recipient_id=? AND id=?`
	msg := relstor.MessageRecord{}
	err := mdp.dbx.Get(&msg, selectSQL, recipientID, msgID)
	switch err {
	case nil:
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "selecting message failed")
	}

	return &msg, nil
}

func (mdp mariaDBProvider) ReplaceAPNSToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_apns_tokens SET token=? WHERE token=?`
	var result sql.Result
	result, err = mdp.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (mdp mariaDBProvider) ReplaceFCMToken(old, new string) (rowsAffected int64, err error) {
	const query = `UPDATE user_fcm_tokens SET token=? WHERE token=?`
	var result sql.Result
	result, err = mdp.dbx.Exec(query, new, old)
	if err != nil {
		return 0, errors.Wrap(err, "Failed to execute update query")
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		return 0, errors.Wrap(err, "Failure trying to get affected rows count")
	}
	return rowsAffected, nil
}

func (mdp mariaDBProvider) SessionChallenge(userID int64) (*relstor.SessionChallengeRecord, error) {
	const challengeSQL = `
	SELECT id, creation_date, challenge FROM session_challenges WHERE user_id=?`
	var challenge relstor.SessionChallengeRecord
	err := mdp.dbx.QueryRowx(challengeSQL, userID).StructScan(&challenge)
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

func (mdp mariaDBProvider) UpdateUserIDOfAPNSToken(newUserID int64, token string) error {
	const query = `UPDATE user_apns_tokens SET user_id=? WHERE token=?`
	_, err := mdp.dbx.Exec(query, newUserID, token)
	return err
}

func (mdp mariaDBProvider) UpdateUserIDOfFCMToken(newUserID int64, token string) error {
	const query = `UPDATE user_fcm_tokens SET user_id=? WHERE token=?`
	_, err := mdp.dbx.Exec(query, newUserID, token)
	return err
}

func (mdp mariaDBProvider) User(username string) (*relstor.UserRecord, error) {
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
	err := mdp.dbx.Get(&user, query, username)
	switch err {
	case nil:
		return &user, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (mdp mariaDBProvider) Username(userID int64) string {
	var username sql.NullString
	err := mdp.dbx.QueryRow("SELECT username FROM users WHERE id=?", userID).Scan(&username)
	if err != nil {
		return ""
	}
	return username.String
}

func (mdp mariaDBProvider) UsernameAvailable(username string) (bool, error) {
	checkUsernameSQL := "SELECT id FROM users WHERE username=?"
	var foundID int
	err := mdp.dbx.QueryRow(checkUsernameSQL, username).Scan(&foundID)
	switch err {
	case nil:
		return false, nil
	case sql.ErrNoRows:
		return true, nil
	default:
		return false, errors.Wrap(err, "error checking if username is available")
	}
}

func (mdp mariaDBProvider) UserPublicKey(userID int64) ([]byte, error) {
	selectSQL := `SELECT public_key FROM users WHERE id=?`
	var pubKey []byte
	err := mdp.dbx.QueryRow(selectSQL, userID).Scan(&pubKey)
	switch err {
	case nil:
		return pubKey, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "unable to select user's public key")
	}
}

func (mdp mariaDBProvider) VerifyEmail(email string, userID int64) error {
	tx, err := mdp.dbx.Begin()
	if err != nil {
		return errors.Wrap(err, "unable to start a transaction")
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE users SET email=? WHERE id=?", email, userID)
	if err != nil {
		return errors.Wrap(err, "unable to update users table")
	}
	_, err = tx.Exec("DELETE FROM "+tableEmailVerificationTokens+" WHERE user_id=?", userID)
	if err != nil {
		return errors.Wrap(err, "unable to delete verification token from table")
	}

	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}

	return nil
}
