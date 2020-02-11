package sqlite

var migrationQueries001 = []string{
	`CREATE TABLE email_verification_tokens (
				  user_id INTEGER PRIMARY KEY,
				  token TEXT NOT NULL,
				  email TEXT NOT NULL,
				  send_date INTEGER NOT NULL)`,
	`CREATE TABLE messages (id INTEGER PRIMARY KEY,
							recipient_id INTEGER NOT NULL,
							sender_id INTEGER NOT NULL,
							cipher_text BLOB NOT NULL,
							nonce BLOB NOT NULL,
							sent_date INTEGER NOT NULL)`,
	`CREATE TABLE session_challenges (id INTEGER PRIMARY KEY,
									  user_id INTEGER NOT NULL,
									  creation_date INTEGER NOT NULL,
									  challenge BLOB NOT NULL)`,
	`CREATE TABLE user_apns_tokens (id INTEGER PRIMARY KEY,
									user_id INTEGER NOT NULL,
									token TEXT NOT NULL)`,
	`CREATE TABLE user_fcm_tokens (id INTEGER PRIMARY KEY,
								   user_id INTEGER NOT NULL,
								   token TEXT NOT NULL)`,
	`CREATE TABLE users (id INTEGER PRIMARY KEY,
						 username TEXT NOT NULL,
						 public_key BLOB NOT NULL,
						 wrapped_secret_key BLOB NOT NULL,
						 wrapped_secret_key_nonce BLOB NOT NULL,
						 wrapped_symmetric_key BLOB NOT NULL,
						 wrapped_symmetric_key_nonce BLOB NOT NULL,
						 password_salt BLOB NOT NULL,
						 password_hash_algorithm TEXT NOT NULL,
						 password_hash_operations_limit INTEGER NOT NULL,
						 password_hash_memory_limit INTEGER NOT NULL,
						 email TEXT)`,
}

var migrationQueries002 = []string{
	`CREATE TABLE tickets (
				  ticket TEXT NOT NULL PRIMARY KEY,
				  user_id INTEGER NOT NULL,
				  timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')))`,
}

var migrationQueries003 = []string{
	`CREATE UNIQUE INDEX users_username_unique_constraint ON users(username)`,
}
