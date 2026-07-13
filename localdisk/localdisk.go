package localdisk

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"zood.dev/oscar/filestor"
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

func (ldp localDiskProvider) DeleteFile(relPath string) error {
	if err := os.Remove(filepath.Join(ldp.rootDir, relPath)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", relPath, filestor.ErrFileNotExist)
		}
		return err
	}

	return nil
}

func (ldp localDiskProvider) ReadFile(relPath string, dst io.Writer) error {
	fp := filepath.Join(ldp.rootDir, relPath)
	f, err := os.Open(fp)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", relPath, filestor.ErrFileNotExist)
		}
		return err
	}
	defer f.Close()

	_, err = io.Copy(dst, f)
	return err
}

func (ldp localDiskProvider) WriteFile(relPath string, src io.Reader) error {
	fp := filepath.Join(ldp.rootDir, relPath)
	// make sure all the directories in the path exist
	dir := filepath.Dir(fp)
	err := os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}

	f, err := os.Create(fp)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, src)
	return err
}
