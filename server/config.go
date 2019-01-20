package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"zood.xyz/oscar/boltdb"
	"zood.xyz/oscar/gcs"
	"zood.xyz/oscar/localdisk"
	"zood.xyz/oscar/mailgun"
	"zood.xyz/oscar/mariadb"
	"zood.xyz/oscar/sodium"

	"github.com/pkg/errors"
)

type configuration struct {
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
	Email struct {
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

func applyConfigFile(confPath string) (*configuration, error) {
	f, err := os.Open(confPath)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open config file")
	}

	conf := configuration{}
	err = json.NewDecoder(f).Decode(&conf)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse config file")
	}

	// symmetric key
	oscarSymKey, err = hex.DecodeString(conf.SymmetricKey)
	if err != nil {
		return nil, errors.Wrap(err, "sym key decode failed")
	}
	if len(oscarSymKey) != sodium.SymmetricKeySize {
		return nil, fmt.Errorf("invalid sym key size (%d); should be %d bytes", len(oscarSymKey), sodium.SymmetricKeySize)
	}

	// public/private keys
	oscarKeyPair.Public, err = hex.DecodeString(conf.AsymmetricKeys.Public)
	if err != nil {
		return nil, errors.Wrap(err, "asym public key decode failed")
	}
	oscarKeyPair.Secret, err = hex.DecodeString(conf.AsymmetricKeys.Secret)
	if err != nil {
		return nil, errors.Wrap(err, "asym secret key decode failed")
	}
	if len(oscarKeyPair.Public) != sodium.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size (%d); should be %d bytes", len(oscarKeyPair.Public), sodium.PublicKeySize)
	}
	if len(oscarKeyPair.Secret) != sodium.SecretKeySize {
		return nil, fmt.Errorf("invalid secret key size (%d); should be %d bytes", len(oscarKeyPair.Secret), sodium.SecretKeySize)
	}

	// Firebase cloud messaging
	if conf.FCMServerKey == "" {
		return nil, errors.New("fcm_server_key is empty/missing")
	}
	gFCMServerKey = conf.FCMServerKey

	// Apple push notifications
	if conf.APNS.KeyID == "" {
		return nil, errors.New("apns 'key_id' is empty/missing")
	}
	if conf.APNS.P8Path == "" {
		return nil, errors.New("apns 'p8_path' is empty/missing")
	}
	if conf.APNS.TeamID == "" {
		return nil, errors.New("apns 'team_id' is empty/missing")
	}
	err = createAPNSClient(conf.APNS.P8Path, conf.APNS.KeyID, conf.APNS.TeamID, conf.APNS.Production)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up apple push notification service client")
	}

	// sql database
	rs, err = mariadb.New(conf.SQLDSN)
	if err != nil {
		return nil, err
	}

	// key-value database
	kvs, err = boltdb.New(conf.KVDBPath)
	if err != nil {
		return nil, errors.Wrap(err, "kv db init failed")
	}

	// set up our file storage
	switch conf.FileStorage.Type {
	case "localdisk":
		fs, err = localdisk.New(conf.FileStorage.LocalDiskStoragePath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init localdisk storage")
		}
	case "gcs":
		fs, err = gcs.New(conf.FileStorage.GCPCredentialsPath, conf.FileStorage.GCPBucketName)
		if err != nil {
			return nil, errors.Wrap(err, "failed to init google cloud storage")
		}
	default:
		return nil, errors.Errorf("unknown 'file_storage' type: %s", conf.FileStorage.Type)
	}

	// TLS info
	if conf.Port == nil {
		port := 443
		conf.Port = &port
	}

	if conf.TLS == nil {
		tls := true
		conf.TLS = &tls
	}
	if *conf.TLS {
		// make sure we have a hostname
		if conf.Hostname == "" {
			return nil, errors.New("Hostname is required when TLS is enabled")
		}
	}

	// mailgun info
	if conf.Email.MailgunAPIKey == "" {
		return nil, errors.New("mailgun api key is missing")
	}
	if conf.Email.Domain == "" {
		return nil, errors.New("email domain is missing")
	}
	mailgun.APIKey = conf.Email.MailgunAPIKey
	mailgun.Domain = conf.Email.Domain

	return &conf, nil
}
