package base62

import (
	"testing"
)

func TestRand(t *testing.T) {
	for i := uint(0); i < 64; i++ {
		s := Rand(i)
		if uint(len(s)) != i {
			t.Fatalf("Incorrect size. %d != %d", len(s), i)
		}
	}
}
