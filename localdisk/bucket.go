package localdisk

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"pijun.io/oscar/filestor"
)

// localDiskBucket satisfies the filestor.Bucket interface
type localDiskBucket struct {
	dir string
}

func (ldb localDiskBucket) Create() error {
	return os.MkdirAll(ldb.dir, 0755)
}

func (ldb localDiskBucket) Exists() (bool, error) {
	_, err := os.Stat(ldb.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (ldb localDiskBucket) ObjectExists(name string) (bool, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return false, filestor.ErrInvalidName
	}
	p := filepath.Join(ldb.dir, name)
	_, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (ldb localDiskBucket) WriteObject(name string, src io.Reader) error {
	if strings.ContainsRune(name, os.PathSeparator) {
		return filestor.ErrInvalidName
	}
	p := filepath.Join(ldb.dir, name)
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, src)
	return err
}

func (ldb localDiskBucket) ReadObject(name string, dst io.Writer) error {
	if strings.ContainsRune(name, os.PathSeparator) {
		return filestor.ErrInvalidName
	}

	p := filepath.Join(ldb.dir, name)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(dst, f)
	return err
}
