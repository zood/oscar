package model

import "errors"

var ErrDuplicateUsername = errors.New("a user with that username already exists")

type AccessTokenRecord struct {
	Token     string `db:"token"`
	UserID    int64  `db:"user_id"`
	ExpiresAt int64  `db:"expires_at"`
}

// APNSTokenRecord represents a row in the user_apns_tokens table
type APNSTokenRecord struct {
	ID     int64  `db:"id"`
	UserID int64  `db:"user_id"`
	Token  string `db:"token"`
}

// EmailVerificationTokenRecord represents a row in the email_verification_tokens table
type EmailVerificationTokenRecord struct {
	UserID   int64  `db:"user_id"`
	Token    string `db:"token"`
	Email    string `db:"email"`
	SendDate int64  `db:"send_date"`
}

// FCMTokenRecord represents a row in the user_fcm_tokens table
type FCMTokenRecord struct {
	ID     int64  `db:"id"`
	UserID int64  `db:"user_id"`
	Token  string `db:"token"`
}

// MessageRecord represents a row in the messages table
type MessageRecord struct {
	ID          int64  `db:"id"`
	RecipientID int64  `db:"recipient_id"`
	SenderID    int64  `db:"sender_id"`
	CipherText  []byte `db:"cipher_text"`
	Nonce       []byte `db:"nonce"`
	SentDate    int64  `db:"sent_date"`
}

// SessionChallengeRecord represents a row in the session_challenges table
type SessionChallengeRecord struct {
	ID           int64  `db:"id"`
	UserID       int64  `db:"user_id"`
	CreationDate int64  `db:"creation_date"`
	Challenge    []byte `db:"challenge"`
}

// UserRecord represents a row in the users table
type UserRecord struct {
	ID                          int64   `db:"id"`
	Username                    string  `db:"username"`
	PublicKey                   []byte  `db:"public_key"`
	WrappedSecretKey            []byte  `db:"wrapped_secret_key"`
	WrappedSecretKeyNonce       []byte  `db:"wrapped_secret_key_nonce"`
	WrappedSymmetricKey         []byte  `db:"wrapped_symmetric_key"`
	WrappedSymmetricKeyNonce    []byte  `db:"wrapped_symmetric_key_nonce"`
	PasswordSalt                []byte  `db:"password_salt"`
	PasswordHashAlgorithm       string  `db:"password_hash_algorithm"`
	PasswordHashOperationsLimit uint    `db:"password_hash_operations_limit"`
	PasswordHashMemoryLimit     uint64  `db:"password_hash_memory_limit"`
	Email                       *string `db:"email"`
}
