package main

import (
	"encoding/json"
	"testing"
)

func TestInt64ToBytesConversion(t *testing.T) {
	var before int64 = 3
	beforeBytes := int64ToBytes(before)

	after := bytesToInt64(beforeBytes)
	if after != before {
		t.Fatalf("%d != %d", before, after)
	}
}

func BenchmarkStructSerialization(b *testing.B) {
	for b.Loop() {
		v := struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}{ID: "foo", Token: "abcdefghijklmnopqrstuvwxyz"}
		buf, err := json.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		if len(buf) == 0 {
			b.Fatal("buf is zero length")
		}
	}
}

func BenchmarkMapSerialization(b *testing.B) {
	for b.Loop() {
		v := map[string]interface{}{
			"id":    "foo",
			"token": "abcdefghijklmnopqrstuvwxyz",
		}
		buf, err := json.Marshal(v)
		if err != nil {
			b.Fatal(err)
		}
		if len(buf) == 0 {
			b.Fatal("buf is zero length")
		}
	}
}
