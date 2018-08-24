package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type oscarError struct {
	Code    uint   `json:"error_code"`
	Message string `json:"error_message"`
}

func (oe oscarError) Error() string {
	return fmt.Sprintf("{ code: %d, message: \"%s\" }", oe.Code, oe.Message)
}

func readError(rdr io.Reader) error {
	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		return err
	}

	// try to parse it into an oscar error
	oscErr := oscarError{}
	if err = json.Unmarshal(data, &oscErr); err != nil {
		return errors.New(string(data))
	}
	if oscErr.Code == 0 || oscErr.Message == "" {
		return errors.New(string(data))
	}

	return oscErr
}
