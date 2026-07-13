package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
	"zood.dev/oscar/filestor"
)

type gcsProvider struct {
	bucket *storage.BucketHandle
	client *storage.Client
}

// New returns a filestor.Provider backed by Google Cloud Storage
func New(credsPath, bucketName string) (filestor.Provider, error) {
	if credsPath == "" {
		return nil, errors.New("must provide the credentials file path")
	}
	if bucketName == "" {
		return nil, errors.New("must provide a bucket name")
	}
	client, err := storage.NewClient(context.Background(), option.WithCredentialsFile(credsPath))
	if err != nil {
		return nil, err
	}
	bkt := client.Bucket(bucketName)
	_, err = bkt.Attrs(context.Background())
	if err != nil {
		return nil, err
	}

	return gcsProvider{
		bucket: bkt,
		client: client,
	}, nil
}

func (gp gcsProvider) DeleteFile(relPath string) error {
	if err := gp.bucket.Object(relPath).Delete(context.Background()); err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return fmt.Errorf("%s: %w", relPath, filestor.ErrFileNotExist)
		}
		return err
	}

	return nil
}

func (gp gcsProvider) ReadFile(relPath string, dst io.Writer) error {
	obj := gp.bucket.Object(relPath)
	rdr, err := obj.NewReader(context.Background())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return fmt.Errorf("%s: %w", relPath, filestor.ErrFileNotExist)
		}
		return err
	}

	_, err = io.Copy(dst, rdr)
	return err
}

func (gp gcsProvider) WriteFile(relPath string, src io.Reader) error {
	obj := gp.bucket.Object(relPath)
	dst := obj.NewWriter(context.Background())
	defer dst.Close()
	_, err := io.Copy(dst, src)
	return err
}
