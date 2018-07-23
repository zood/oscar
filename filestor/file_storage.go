package filestor

import (
	"errors"
	"io"
)

// ErrInvalidName indicates the Bucket or Object name is invalid
var ErrInvalidName = errors.New("Invalid name")

// Provider is the set of functionality required by oscar of a file storage system.
// The interface exists to make it easy to swap out storage mechanisms (local disk,
// google cloud storage, aws s3, etc.)
type Provider interface {
	Bucket(name string) (Bucket, error)
}

// Bucket represents a directory or a cloud storage bucket
type Bucket interface {
	Create() error
	Exists() (bool, error)
	ObjectExists(name string) (bool, error)
	WriteObject(name string, src io.Reader) error
	ReadObject(name string, dst io.Writer) error
}