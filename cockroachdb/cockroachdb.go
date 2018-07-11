package cockroachdb

import (
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"pijun.io/oscar/relstor"
)

const (
	tableEmailVerificationTokens string = "email_verification_tokens"
	tableMessages                       = "messages"
	tableSessionChallenges              = "session_challenges"
	tableUserFCMTokens                  = "user_fcm_tokens"
	tableUsers                          = "users"
)

type cockroachDBProvider struct {
	dbx *sqlx.DB
}

// New returns a relstor.Provider backed by a cockroach db instance
func New(connURI string) (*cockroachDBProvider, error) {
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

	_, err = sqlxdb.Exec("SET database = pijunDb")
	if err != nil {
		return nil, errors.Wrap(err, "unable to set database")
	}

	return &cockroachDBProvider{dbx: sqlxdb}, nil
}

func (cdb cockroachDBProvider) InsertUser(user relstor.UserRecord, verificationToken *string) (int64, error) {
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
	defer rows.Next()
	var userID int64
	if rows.Next() {
		err = rows.Scan(&userID)
		if err != nil {
			return 0, errors.Wrap(err, "unable to obtain id of new user record")
		}
	} else {
		return 0, errors.New("failed to iterate rows to get user id")
	}
	// if err != nil {
	// 	return 0, errors.Wrap(err, "failed to insert user into table")
	// }
	// userID, err := result.LastInsertId()
	// if err != nil {
	// 	return 0, errors.Wrap(err, "unable to obtain id of new user record")
	// }

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

func (cdb cockroachDBProvider) User(username string) (*relstor.UserRecord, error) {
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
