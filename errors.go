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
	ErrorNone                            ErrCode = 0
	ErrorInternal                                = 1
	ErrorBadRequest                              = 2
	ErrorInvalidUsername                         = 3
	ErrorInvalidPublicKey                        = 4
	ErrorInvalidWrappedSecretKey                 = 5
	ErrorInvalidWrappedSecretKeyNonce            = 6
	ErrorInvalidWrappedSymmetricKey              = 7
	ErrorInvalidWrappedSymmetricKeyNonce         = 8
	ErrorInvalidPasswordSalt                     = 9
	ErrorUsernameNotAvailable                    = 10
	ErrorNotFound                                = 11
	ErrorInsufficientPermission                  = 12
	ErrorArgon2iOpsLimitTooLow                   = 13
	ErrorArgon2iMemLimitTooLow                   = 14
	ErrorInvalidAccessToken                      = 15
	ErrorUserNotFound                            = 16
	ErrorChallengeNotFound                       = 17
	ErrorChallengeExpired                        = 18
	ErrorLoginFailed                             = 19
	ErrorBackupNotFound                          = 20
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
	return &serverError{code: ErrorInternal, message: "Internal server error"}
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
