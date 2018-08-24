package main

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"testing"

	"zood.xyz/oscar/sodium"
)

const dropBoxIDSize = 16

func TestPackageDropping(t *testing.T) {
	user := createUserOnServer(t)
	accessToken := login(user, t)

	pkg := []byte("N. Bluth")
	boxID := make([]byte, dropBoxIDSize)
	sodium.Random(boxID)

	req, _ := http.NewRequest(http.MethodPut, apiRoot+"/alpha/drop-boxes/"+hex.EncodeToString(boxID), bytes.NewReader(pkg))
	req.Header.Add("X-Oscar-Access-Token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	// now try to pick it up
	req, _ = http.NewRequest(http.MethodGet, apiRoot+"/alpha/drop-boxes/"+hex.EncodeToString(boxID), nil)
	req.Header.Add("X-Oscar-Access-Token", accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	rcvdPkg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rcvdPkg, pkg) {
		t.Fatal("Downloaded package doesn't match what was dropped off")
	}
}
