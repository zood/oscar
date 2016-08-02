package main

// ErrCode ...
type ErrCode int

// Errors used throughout this package
const (
	ErrorNone       ErrCode = 0
	ErrorInternal           = 1
	ErrorBadRequest         = 2
)
