package main

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
)

// ErrCode ...
type ErrCode int

// Errors used throughout this package
const (
	errorNone                            ErrCode = 0
	errorInternal                                = 1
	errorBadRequest                              = 2
	errorInvalidUsername                         = 3
	errorInvalidPublicKey                        = 4
	errorInvalidWrappedSecretKey                 = 5
	errorInvalidWrappedSecretKeyNonce            = 6
	errorInvalidWrappedSymmetricKey              = 7
	errorInvalidWrappedSymmetricKeyNonce         = 8
	errorInvalidPasswordSalt                     = 9
	errorUsernameNotAvailable                    = 10
	errorNotFound                                = 11
	errorInsufficientPermission                  = 12
	errorArgon2iOpsLimitTooLow                   = 13
	errorArgon2iMemLimitTooLow                   = 14
	errorInvalidAccessToken                      = 15
	errorUserNotFound                            = 16
	errorChallengeNotFound                       = 17
	errorChallengeExpired                        = 18
	errorLoginFailed                             = 19
	errorBackupNotFound                          = 20
	errorInvalidEmail                            = 21
	errorMissingVerificationToken                = 22
)

type serverError struct {
	code    ErrCode
	message string
}

func (err serverError) Error() string {
	return err.String()
}

func (err serverError) String() string {
	return fmt.Sprintf("%s (%d)", err.message, err.code)
}

func newInternalErr() *serverError {
	return &serverError{code: errorInternal, message: "Internal server error"}
}

func logErr(err error) {
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}
	file = filepath.Base(file)
	log.Printf("%s:%d %v", file, line, err)
}
