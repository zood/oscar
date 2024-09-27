package main

import (
	"fmt"
)

// ErrCode ...
type ErrCode int

// Errors used throughout this package
const (
	errorNone                            ErrCode = 0
	errorInternal                        ErrCode = 1
	errorBadRequest                      ErrCode = 2
	errorInvalidUsername                 ErrCode = 3
	errorInvalidPublicKey                ErrCode = 4
	errorInvalidWrappedSecretKey         ErrCode = 5
	errorInvalidWrappedSecretKeyNonce    ErrCode = 6
	errorInvalidWrappedSymmetricKey      ErrCode = 7
	errorInvalidWrappedSymmetricKeyNonce ErrCode = 8
	errorInvalidPasswordSalt             ErrCode = 9
	errorUsernameNotAvailable            ErrCode = 10
	errorNotFound                        ErrCode = 11
	errorInsufficientPermission          ErrCode = 12
	errorArgon2iOpsLimitTooLow           ErrCode = 13
	errorArgon2iMemLimitTooLow           ErrCode = 14
	errorInvalidAccessToken              ErrCode = 15
	errorUserNotFound                    ErrCode = 16
	errorChallengeNotFound               ErrCode = 17
	errorChallengeExpired                ErrCode = 18
	errorLoginFailed                     ErrCode = 19
	errorBackupNotFound                  ErrCode = 20
	errorInvalidEmail                    ErrCode = 21
	errorMissingVerificationToken        ErrCode = 22
	errorInvalidPasswordHashAlgorithm    ErrCode = 23
	errorNotAnEndpoint                   ErrCode = 24
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
