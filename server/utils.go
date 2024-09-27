package main

import (
	"bytes"
	"encoding/binary"
)

func int64ToBytes(i int64) []byte {
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, i)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func bytesToInt64(b []byte) int64 {
	var i int64
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, &i)
	if err != nil {
		panic(err)
	}

	return i
}
