package boltdb

import "testing"

func TestRoundtrip(t *testing.T) {
	for i := int64(0); i < 10000; i++ {
		b := int64ToBytes(i)
		out, err := bytesToInt64(b)
		if err != nil {
			t.Fatal(err)
		}
		if i != out {
			t.Fatalf("Conversion failed for %d. Got %d.", i, out)
		}
	}
}

func TestBytesToInt64(t *testing.T) {
	_, err := bytesToInt64(nil)
	if err == nil {
		t.Fatalf("Expecting an error with nil data, but no error was received")
	}

	i, err := bytesToInt64([]byte{1, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if i != 1 {
		t.Fatalf("%d != 1", i)
	}
}
