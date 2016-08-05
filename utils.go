package main

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"strings"
)

var gAlphaNums = strings.Split("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "")

func randAlphaNum(length int) string {
	s := ""
	numRunes := uint64(len(gAlphaNums))
	for i := 0; i < length; i++ {
		idx := crandUint64n(numRunes)
		s += gAlphaNums[idx]
	}

	return s
}

func crandUint64n(n uint64) uint64 {
	bigN := (&big.Int{}).SetUint64(n)
	val, err := crand.Int(crand.Reader, bigN)
	if err != nil {
		logErr(err)
		// fall back to non-crypto rand
		return uint64(rand.Int63n(int64(n)))
	}

	return val.Uint64()
}
