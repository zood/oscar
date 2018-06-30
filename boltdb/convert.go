package boltdb

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

func bytesToInt64(b []byte) (int64, error) {
	var i int64
	if len(b) != 8 {
		return 0, errors.Errorf("Expected 8 bytes. Given %d.", len(b))
	}
	buf := bytes.NewReader(b)
	binary.Read(buf, binary.LittleEndian, &i)

	return i, nil
}

func int64ToBytes(i int64) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, i)
	return buf.Bytes()
}
