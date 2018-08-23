package encodable

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

type message struct {
	Buffer Bytes `json:"buffer"`
}

func TestJSONSerialization(t *testing.T) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}

	msg := message{
		Buffer: buf,
	}

	serialized, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	// make sure a manual deserialization works (not using our json.Unmarshal implementation)
	thirdPartyObj := struct {
		Buffer string `json:"buffer"`
	}{}

	if err = json.Unmarshal(serialized, &thirdPartyObj); err != nil {
		t.Fatal(err)
	}

	manualBuf, err := base64.StdEncoding.DecodeString(thirdPartyObj.Buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, manualBuf) {
		t.Fatal("Manual decoding didn't match the original data")
	}

	// now test our json.Unmarshal implementation
	msg2 := message{}
	if err = json.Unmarshal(serialized, &msg2); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg.Buffer, msg2.Buffer) {
		t.Fatal("We failed to roundtrip the data")
	}
}
