package gcs

import (
	"io"

	"cloud.google.com/go/storage"
)

type gcsBucket struct {
	bkt *storage.BucketHandle
}

func (gb gcsBucket) Create() error {
	return nil
}

func (gb gcsBucket) Exists() (bool, error) {
	return false, nil
}

func (gb gcsBucket) ObjectExists(name string) (bool, error) {
	return false, nil
}

func (gb gcsBucket) WriteObject(name string, src io.Reader) error {
	return nil
}

func (gb gcsBucket) ReadObject(name string, dst io.Writer) error {
	return nil
}
