package encodable

import (
	"database/sql/driver"
	"encoding/base64"
	"errors"
)

// Bytes conforms to the json.Marshal, json.Unmarshal and driver.Value interfaces.
// It's used to simplify serialization of []byte data to the JSON API. The driver.Value
// implementation is to allow ease of use when writing to SQL databases as blobs.
type Bytes []byte

func (eb Bytes) Base64() string {
	return base64.StdEncoding.EncodeToString(eb)
}

// MarshalJSON fulfills the json.Marshal interface
func (eb Bytes) MarshalJSON() ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(eb)))
	base64.StdEncoding.Encode(dst, eb)
	final := append([]byte{'"'}, dst...)
	final = append(final, '"')
	return final, nil
}

// UnmarshalJSON fulfills the json.Unmarshal interface
func (eb *Bytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 {
		return errors.New("byte data must be encoded as a base64 string")
	}
	if data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("base64 string must be surrounded by double quotes")
	}
	encodedData := data[1 : len(data)-1]
	decodedData := make([]byte, base64.StdEncoding.DecodedLen(len(encodedData)))
	l, err := base64.StdEncoding.Decode(decodedData, encodedData)
	if err != nil {
		return err
	}
	// with base64, you have to check the length that it ended up being decoded
	// into, because the value from DecodedLen() is max, not the exact amount
	*eb = decodedData[:l]
	return nil
}

// Value fulfills the driver.Value interface
func (eb Bytes) Value() (driver.Value, error) {
	return []byte(eb), nil
}
