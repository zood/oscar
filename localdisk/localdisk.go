package localdisk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"pijun.io/oscar/filestor"
)

// localDiskProvider satisifies the filestor.Provider interface
type localDiskProvider struct {
	rootDir string
}

// New returns a filestor.Provider backed by the system's local disk
func New(rootDir string) (filestor.Provider, error) {
	if rootDir == "" {
		return nil, errors.New("You need to provide a valid path to localdisk")
	}
	// make sure the path exists
	fi, err := os.Stat(rootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("'%v' does not exist", err)
		}
		return nil, errors.Wrap(err, "failed to stat root directory")
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("'%s' is not a directory", rootDir)
	}

	return localDiskProvider{rootDir: rootDir}, nil
}

func (ldp localDiskProvider) Bucket(name string) (filestor.Bucket, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return nil, filestor.ErrInvalidName
	}

	bucketPath := filepath.Join(ldp.rootDir, name)
	return localDiskBucket{dir: bucketPath}, nil
}
