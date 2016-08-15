package main

import "testing"

func TestInt64ToBytesConversion(t *testing.T) {
	var before int64 = 3
	beforeBytes := int64ToBytes(before)

	after := bytesToInt64(beforeBytes)
	if after != before {
		t.Fatalf("%d != %d", before, after)
	}
}
