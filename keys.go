package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

var oscarKeyPair keyPair
var oscarSymKey []byte

func initAsymmetricKeys(asymKeysPath string) error {
	f, err := os.Open(asymKeysPath)
	if err != nil {
		return errors.Wrap(err, "unable to open symmetric keys file")
	}
	defer f.Close()

	tmp := struct {
		Public string `json:"public"`
		Secret string `json:"secret"`
	}{}
	err = json.NewDecoder(f).Decode(&tmp)
	if err != nil {
		return errors.Wrap(err, "sym key file parse failed")
	}

	oscarKeyPair.public, err = hex.DecodeString(tmp.Public)
	if err != nil {
		return errors.Wrap(err, "failed to decode public key")
	}
	oscarKeyPair.secret, err = hex.DecodeString(tmp.Secret)
	if err != nil {
		return errors.Wrap(err, "failed to decode secret key")
	}

	if len(oscarKeyPair.public) != publicKeySize {
		return fmt.Errorf("invalid public key size (%d); should be %d bytes", len(oscarKeyPair.public), publicKeySize)
	}
	if len(oscarKeyPair.secret) != secretKeySize {
		return fmt.Errorf("invalid secret key size (%d); should be %d bytes", len(oscarKeyPair.secret), secretKeySize)
	}

	return nil
}

func initSymmetricKey(symKeyPath string) error {
	f, err := os.Open(symKeyPath)
	if err != nil {
		return errors.Wrap(err, "unable to open sym key file")
	}

	tmp := struct {
		Key string `json:"key"`
	}{}
	err = json.NewDecoder(f).Decode(&tmp)
	if err != nil {
		return errors.Wrap(err, "unable to parse sym key file")
	}

	oscarSymKey, err = hex.DecodeString(tmp.Key)
	if err != nil {
		return errors.Wrap(err, "sym key decode failed")
	}

	if len(oscarSymKey) != secretBoxKeySize {
		return fmt.Errorf("invalid sym key size (%d); should be %d bytes", len(oscarSymKey), secretBoxKeySize)
	}

	return nil
}

func getServerPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	sendSuccess(w, struct {
		Key encodableBytes `json:"public_key"`
	}{Key: oscarKeyPair.public})
}
