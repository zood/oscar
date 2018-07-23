package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"pijun.io/oscar/boltdb"
	"pijun.io/oscar/localdisk"
	"pijun.io/oscar/mariadb"

	"github.com/pkg/errors"
)

type configuration struct {
	SymmetricKey   string `json:"symmetric_key"`
	AsymmetricKeys struct {
		Public string `json:"public"`
		Secret string `json:"secret"`
	} `json:"asymmetric_keys"`
	SQLDSN               string `json:"sql_dsn"`
	Port                 *int   `json:"port,omitempty"`
	KVDBPath             string `json:"kv_db_path"`
	LocalDiskStoragePath string `json:"local_disk_storage_path"`
	FCMServerKey         string `json:"fcm_server_key"`
	Hostname             string `json:"hostname"`
	TLS                  *bool  `json:"tls,omitempty"`
	Email                struct {
		SMTPUser     string `json:"smtp_user"`
		SMTPPassword string `json:"smtp_password"`
		SMTPServer   string `json:"smtp_server"`
		SMTPPort     int    `json:"smtp_port"`
	}
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
	if len(oscarSymKey) != secretBoxKeySize {
		return nil, fmt.Errorf("invalid sym key size (%d); should be %d bytes", len(oscarSymKey), secretBoxKeySize)
	}

	// public/private keys
	oscarKeyPair.public, err = hex.DecodeString(conf.AsymmetricKeys.Public)
	if err != nil {
		return nil, errors.Wrap(err, "asym public key decode failed")
	}
	oscarKeyPair.secret, err = hex.DecodeString(conf.AsymmetricKeys.Secret)
	if err != nil {
		return nil, errors.Wrap(err, "asym secret key decode failed")
	}
	if len(oscarKeyPair.public) != publicKeySize {
		return nil, fmt.Errorf("invalid public key size (%d); should be %d bytes", len(oscarKeyPair.public), publicKeySize)
	}
	if len(oscarKeyPair.secret) != secretKeySize {
		return nil, fmt.Errorf("invalid secret key size (%d); should be %d bytes", len(oscarKeyPair.secret), secretKeySize)
	}

	// Firebase cloud messaging
	if conf.FCMServerKey == "" {
		return nil, errors.New("fcm_server_key is empty/missing")
	}
	gFCMServerKey = conf.FCMServerKey

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

	// file storage
	fs, err = localdisk.New(conf.LocalDiskStoragePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init localdisk storage")
	}

	// create all the buckets we need
	bkt, err := fs.Bucket(userDBsBucketName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve bucket for user db backups")
	}
	err = bkt.Create()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create bucket for user dbs backup")
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

	// SMTP client info
	emailConfiguration.smtpUser = conf.Email.SMTPUser
	emailConfiguration.smtpPassword = conf.Email.SMTPPassword
	emailConfiguration.smtpServer = conf.Email.SMTPServer
	emailConfiguration.smtpPort = conf.Email.SMTPPort

	return &conf, nil
}
