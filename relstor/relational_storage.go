package relstor

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

// Provider is the set of functionality required by oscar of a relational database.
// The interface exists as an intermediary, so unit tests can be written against the oscar code
// with a stubbed out relational database.
type Provider interface {
	APNSToken(token string) (*APNSTokenRecord, error)
	APNSTokensRaw(userID int64) ([]string, error)
	APNSTokenUser(userID int64, token string) (*APNSTokenRecord, error)
	DeleteAPNSToken(token string) error
	DeleteAPNSTokenOfUser(userID int64, token string) error
	DeleteFCMToken(token string) error
	DeleteFCMTokenOfUser(userID int64, token string) error
	DeleteMessageToRecipient(recipientID, msgID int64) error
	DeleteSessionChallengeID(id int64) error
	DeleteSessionChallengeUser(userID int64) error
	DeleteTickets(olderThan int64) error
	DisavowEmail(token string) error
	EmailVerificationTokenRecord(token string) (*EmailVerificationTokenRecord, error)
	FCMToken(token string) (*FCMTokenRecord, error)
	FCMTokensRaw(userID int64) ([]string, error)
	FCMTokenUser(userID int64, token string) (*FCMTokenRecord, error)
	InsertAPNSToken(userID int64, token string) error
	InsertFCMToken(userID int64, token string) error
	InsertMessage(recipientID, senderID int64, cipherText, nonce []byte, sentDate int64) (int64, error)
	InsertSessionChallenge(userID int64, creationDate int64, challenge []byte) error
	InsertTicket(ticket string, userID int64) error
	InsertUser(user UserRecord, verificationToken *string) (int64, error)
	LimitedUserInfo(username string) (id int64, pubKey []byte, err error)
	LimitedUserInfoID(userID int64) (username string, pubKey []byte, err error)
	MessageRecords(recipientID int64) ([]MessageRecord, error)
	MessageToRecipient(recipientID, msgID int64) (*MessageRecord, error)
	ReplaceAPNSToken(old, new string) (rowsAffected int64, err error)
	ReplaceFCMToken(old, new string) (rowsAffected int64, err error)
	SessionChallenge(userID int64) (*SessionChallengeRecord, error)
	Ticket(ticket string) (userID, timestamp int64, err error)
	UpdateUserIDOfAPNSToken(newUserID int64, token string) error
	UpdateUserIDOfFCMToken(newUserID int64, token string) error
	User(username string) (*UserRecord, error)
	Username(userID int64) string
	UsernameAvailable(username string) (bool, error)
	UserPublicKey(userID int64) ([]byte, error)
	VerifyEmail(email string, userID int64) error
}
