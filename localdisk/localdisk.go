package localdisk

import (
	"path/filepath"
	"strings"

	"pijun.io/oscar/filestor"
)

// localDiskProvider satisifies the filestor.Provider interface
type localDiskProvider struct {
	rootDir string
}

// New returns a filestor.Provider backed by the system's local disk
func New(rootDir string) filestor.Provider {
	return localDiskProvider{rootDir: rootDir}
}

func (ldp localDiskProvider) Bucket(name string) (filestor.Bucket, error) {
	if strings.Contains(name, "/") {
		return nil, filestor.InvalidBucketName
	}

	bucketPath := filepath.Join(ldp.rootDir, name)
	return localDiskBucket{dir: bucketPath}, nil
}
