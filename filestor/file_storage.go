package filestor

import (
	"errors"
	"io"
)

// Provider is the set of functionality required by oscar of a file storage system.
type Provider interface {
	ReadFile(relPath string, dst io.Writer) error
	WriteFile(relPath string, src io.Reader) error
}

// ErrFileNotExist indicates the files does not exist
var ErrFileNotExist = errors.New("file does not exist")
