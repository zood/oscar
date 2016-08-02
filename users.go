package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
)

// User ...
type User struct {
	ID                int
	Email             string
	PublicKey         []byte
	WrappedPrivateKey []byte
}

// CreateUserHandler handles POST /users
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	user := struct {
		Email               string `json:"email"`
		PEMEncodedPublicKey string `json:"public_key"`
	}{}

	// buf, _ := ioutil.ReadAll(r.Body)
	// log.Print(string(buf))

	dec := json.NewDecoder(r.Body)
	err := dec.Decode(&user)
	if err != nil {
		log.Printf("can't parse body: " + err.Error())
		sendBadReq(w, "Unable to parse POST body: "+err.Error())
		return
	}

	block, _ := pem.Decode([]byte(user.PEMEncodedPublicKey))
	if block == nil {
		log.Printf("unable to decode pem")
		return
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("error parsing pkix: %v", err)
		return
	}
	log.Printf("pubKey: %v", pubKey)
	// keyBytes, err := base64.StdEncoding.DecodeString(user.PEMEncodedPublicKey)
	// if err != nil {
	// 	sendBadReq(w, "Unable to base64 decode public key: "+err.Error())
	// 	return
	// }
	// pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	// if err != nil {
	// 	log.Printf("unable to parse pkix: %v", err)
	// 	return
	// }
	// log.Printf("pubKey: %v", pubKey)
}
