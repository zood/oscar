package main

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"zood.xyz/oscar/mailgun"
	"zood.xyz/oscar/sodium"

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
		Public string `json:"public"`
		Secret string `json:"secret"`
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
	FCMServerKey string `json:"fcm_server_key"`
	Hostname     string `json:"hostname"`
	KVDBPath     string `json:"kv_db_path"`
	Port         *int   `json:"port,omitempty"`
	SQLDSN       string `json:"sql_dsn"`
	SymmetricKey string `json:"symmetric_key"`
	TLS          *bool  `json:"tls,omitempty"`
}

var config *serverConfig

func applyConfigFile(confPath string) (*serverConfig, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open config file")
	}

	cfg := serverConfig{}
	err = json.NewDecoder(f).Decode(&cfg)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse config file")
	}

	// symmetric key
	oscarSymKey, err = hex.DecodeString(cfg.SymmetricKey)
	if err != nil {
		return nil, errors.Wrap(err, "sym key decode failed")
	}
	if len(oscarSymKey) != sodium.SymmetricKeySize {
		return nil, errors.Errorf("invalid sym key size (%d); should be %d bytes", len(oscarSymKey), sodium.SymmetricKeySize)
	}

	if cfg.AutocertDirCache == "" {
		return nil, errors.New("'autocert_dir_cache' field is missing")
	}

	// public/private keys
	oscarKeyPair.Public, err = hex.DecodeString(cfg.AsymmetricKeys.Public)
	if err != nil {
		return nil, errors.Wrap(err, "asym public key decode failed")
	}
	oscarKeyPair.Secret, err = hex.DecodeString(cfg.AsymmetricKeys.Secret)
	if err != nil {
		return nil, errors.Wrap(err, "asym secret key decode failed")
	}
	if len(oscarKeyPair.Public) != sodium.PublicKeySize {
		return nil, errors.Errorf("invalid public key size (%d); should be %d bytes", len(oscarKeyPair.Public), sodium.PublicKeySize)
	}
	if len(oscarKeyPair.Secret) != sodium.SecretKeySize {
		return nil, errors.Errorf("invalid secret key size (%d); should be %d bytes", len(oscarKeyPair.Secret), sodium.SecretKeySize)
	}

	// Firebase cloud messaging
	if cfg.FCMServerKey == "" {
		return nil, errors.New("fcm_server_key is empty/missing")
	}
	gFCMServerKey = cfg.FCMServerKey

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
	if cfg.SQLDSN == "" {
		return nil, errors.New("'sql_dsn' is empty/missing")
	}

	// key-value database
	if cfg.KVDBPath == "" {
		return nil, errors.New("'kv_db_path' is empty/missing")
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
	mailgun.APIKey = cfg.Email.MailgunAPIKey
	mailgun.Domain = cfg.Email.Domain

	return &cfg, nil
}
