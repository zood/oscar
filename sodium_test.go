package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHashData(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatal(err)
	}

	data1 := []byte("this is some data")
	data2 := []byte("this is some data")
	data3 := []byte("something else data please")

	hash1, ok := hashData(data1, key)
	if !ok {
		t.Fatal("data1 hash failed")
	}
	if len(hash1) == 0 {
		t.Fatal("first hash failed, because 0 length")
	}

	hash2, ok := hashData(data2, key)
	if !ok {
		t.Fatal("data2 hash failed")
	}
	if !bytes.Equal(hash1, hash2) {
		t.Fatal("hash1 and hash2 are supposed to be equal")
	}

	hash3, ok := hashData(data3, key)
	if !ok {
		t.Fatal("data3 hash failed")
	}
	if len(hash3) == 0 {
		t.Fatal("hash3 failed, because 0 length")
	}
	if bytes.Equal(hash3, hash1) {
		t.Fatal("hash3 equals a hash it's not supposed to match")
	}
}
