package gcs

import (
	"context"
	"errors"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"pijun.io/oscar/filestor"
)

type gcsProvider struct {
	client    *storage.Client
	projectID string
}

// New returns a filestor.Provider backed by Google Cloud Storage
func New(projectID string) (filestor.Provider, error) {
	if projectID == "" {
		return nil, errors.New("project id is missing")
	}
	client, err := storage.NewClient(context.Background())
	if err != nil {
		return nil, err
	}

	return gcsProvider{
		client:    client,
		projectID: projectID,
	}, nil
}

func (gp gcsProvider) Bucket(name string) (filestor.Bucket, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return nil, filestor.ErrInvalidName
	}
	return gcsBucket{bkt: gp.client.Bucket(name)}, nil
}
