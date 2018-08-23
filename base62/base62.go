package base62

import (
	crand "crypto/rand"
	"strings"
)

var base62Chars = strings.Split("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "")

// Rand returns a base62 string of size length
func Rand(length uint) string {
	s := ""
	for i := uint(0); i < length; i++ {
		idx := randUint8() % 62
		s += base62Chars[idx]
	}

	return s
}

func randUint8() uint8 {
	b := make([]byte, 1)
	if _, err := crand.Read(b); err != nil {
		panic(err)
	}

	return uint8(b[0])
}
