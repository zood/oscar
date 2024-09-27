package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"zood.dev/oscar/sodium"

	"github.com/pkg/errors"
)

type serverConfig struct {
	APNS struct {
		KeyID      string `json:"key_id"`
		P8Path     string `json:"p8_path"`
		Production bool   `json:"production"`
		TeamID     string `json:"team_id"`
	} `json:"apns"`
	AsymmetricKeys struct {
		PublicHex string `json:"public"`
		Public    []byte `json:"-"`
		SecretHex string `json:"secret"`
		Secret    []byte `json:"-"`
	} `json:"asymmetric_keys"`
	AutocertDirCache string `json:"autocert_dir_cache"`
	Email            struct {
		MailgunAPIKey string `json:"mailgun_api_key"`
		Domain        string `json:"domain"`
	} `json:"email"`
	FileStorage struct {
		Type                 string `json:"type"`
		GCPBucketName        string `json:"gcp_bucket_name"`
		GCPCredentialsPath   string `json:"gcp_credentials_path"`
		LocalDiskStoragePath string `json:"local_disk_storage_path"`
	} `json:"file_storage"`
	FCMCredentialsPath string `json:"fcm_credentials_path"`
	Hostname           string `json:"hostname"`
	KVDBDirectory      string `json:"kv_db_directory"`
	Port               *int   `json:"port,omitempty"`
	SQLDBDirectory     string `json:"sql_db_directory"`
	SymmetricKey       []byte `json:"-"`
	SymmetricKeyHex    string `json:"symmetric_key"`
	TLS                *bool  `json:"tls,omitempty"`
}

func loadConfig(confPath string) (*serverConfig, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open config file")
	}

	cfg := serverConfig{}
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&cfg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse config file")
	}

	// symmetric key
	cfg.SymmetricKey, err = hex.DecodeString(cfg.SymmetricKeyHex)
	if err != nil {
		return nil, errors.Wrap(err, "sym key decode failed")
	}
	if len(cfg.SymmetricKey) != sodium.SymmetricKeySize {
		return nil, errors.Errorf("invalid sym key size (%d); should be %d bytes", len(cfg.SymmetricKey), sodium.SymmetricKeySize)
	}

	if cfg.AutocertDirCache == "" {
		return nil, errors.New("'autocert_dir_cache' field is missing")
	}

	// public/private keys
	cfg.AsymmetricKeys.Public, err = hex.DecodeString(cfg.AsymmetricKeys.PublicHex)
	if err != nil {
		return nil, errors.Wrap(err, "asym public key decode failed")
	}
	cfg.AsymmetricKeys.Secret, err = hex.DecodeString(cfg.AsymmetricKeys.SecretHex)
	if err != nil {
		return nil, errors.Wrap(err, "asym secret key decode failed")
	}
	if len(cfg.AsymmetricKeys.Public) != sodium.PublicKeySize {
		return nil, errors.Errorf("invalid public key size (%d); should be %d bytes", len(cfg.AsymmetricKeys.Public), sodium.PublicKeySize)
	}
	if len(cfg.AsymmetricKeys.Secret) != sodium.SecretKeySize {
		return nil, errors.Errorf("invalid secret key size (%d); should be %d bytes", len(cfg.AsymmetricKeys.Secret), sodium.SecretKeySize)
	}

	// Firebase cloud messaging
	if cfg.FCMCredentialsPath == "" {
		return nil, errors.New("fcm_credentials_path is empty/missing")
	}

	// Apple push notifications
	if cfg.APNS.KeyID == "" {
		return nil, errors.New("apns 'key_id' is empty/missing")
	}
	if cfg.APNS.P8Path == "" {
		return nil, errors.New("apns 'p8_path' is empty/missing")
	}
	if cfg.APNS.TeamID == "" {
		return nil, errors.New("apns 'team_id' is empty/missing")
	}
	err = createAPNSClient(cfg.APNS.P8Path, cfg.APNS.KeyID, cfg.APNS.TeamID, cfg.APNS.Production)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up apple push notification service client")
	}

	// sql database
	if cfg.SQLDBDirectory == "" {
		return nil, fmt.Errorf("'sql_db_directory' is empty/missing")
	}
	if fi, err := os.Stat(cfg.SQLDBDirectory); err != nil {
		return nil, fmt.Errorf("while stat'ing sql_db_directory: %w", err)
	} else {
		if !fi.IsDir() {
			return nil, fmt.Errorf("'%s' is not a directory. need a directory for 'sql_db_directory'", cfg.SQLDBDirectory)
		}
	}

	// key-value database
	if cfg.KVDBDirectory == "" {
		return nil, fmt.Errorf("'kv_db_directory' is empty/missing")
	}
	if fi, err := os.Stat(cfg.KVDBDirectory); err != nil {
		return nil, fmt.Errorf("while stat'ing kv_db_directory: %w", err)
	} else {
		if !fi.IsDir() {
			return nil, fmt.Errorf("'%s' is not a directory. need a directory for 'kv_db_directory'", cfg.KVDBDirectory)
		}
	}

	// set up our file storage
	if cfg.FileStorage.Type != "localdisk" && cfg.FileStorage.Type != "gcs" {
		return nil, errors.Errorf("unknown filestor provider: '%s'", cfg.FileStorage.Type)
	}

	// TLS info
	if cfg.Port == nil {
		port := 443
		cfg.Port = &port
	}

	if cfg.TLS == nil {
		tls := true
		cfg.TLS = &tls
	}
	if *cfg.TLS {
		// make sure we have a hostname
		if cfg.Hostname == "" {
			return nil, errors.New("Hostname is required when TLS is enabled")
		}
	}

	// mailgun info
	if cfg.Email.MailgunAPIKey == "" {
		return nil, errors.New("mailgun api key is missing")
	}
	if cfg.Email.Domain == "" {
		return nil, errors.New("email domain is missing")
	}

	return &cfg, nil
}
