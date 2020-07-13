package gcs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/filestor"
)

var testDir string

func provider(t *testing.T) filestor.Provider {
	t.Helper()
	p, err := New("/home/arash/coding/zood/api-env/gcp-credentials.json", "dev-api-zood-xyz")
	require.NoError(t, err)

	return p
}

func TestMain(m *testing.M) {
	testDir = fmt.Sprintf("unittest-%d", time.Now().UnixNano())

	// run the tests
	os.Exit(m.Run())
}

func TestProviderCreation(t *testing.T) {
	t.Parallel()

	_, err := New("", "")
	require.Error(t, err)

	_, err = New("/home/arash/coding/zood/api-env/gcp-credentials.json", "")
	require.Error(t, err)

	p, err := New("/home/arash/coding/zood/api-env/gcp-credentials.json", "dev-api-zood-xyz")
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestReadNonExistentObject(t *testing.T) {
	t.Parallel()

	p := provider(t)
	fp := filepath.Join(testDir, "should-not-exist")

	dst := &bytes.Buffer{}
	err := p.ReadFile(fp, dst)
	if err != filestor.ErrFileNotExist {
		t.Fatalf("Should have received 'file not exist'. Got %v", err)
	}
}

func TestWriteNewFile(t *testing.T) {
	t.Parallel()

	p := provider(t)
	fp := filepath.Join(testDir, "lyrics.txt")

	data := []byte("Hello, darkness, my old friend")
	src := bytes.NewBuffer(data)
	err := p.WriteFile(fp, src)
	if err != nil {
		t.Fatal(err)
	}

	// read it back
	dst := &bytes.Buffer{}
	err = p.ReadFile(fp, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), data) {
		t.Fatalf("data read back is not correct. Got '%s'", dst.String())
	}
}

func TestUpdateFile(t *testing.T) {
	t.Parallel()

	p := provider(t)
	fp := filepath.Join(testDir, "list.txt")
	data1 := []byte("*Eggs\n*Milk\n")
	src := bytes.NewBuffer(data1)
	p.WriteFile(fp, src)

	// now overwrite it
	data2 := []byte("*Eggs\n*Milk\n*Orange juice\n")
	src = bytes.NewBuffer(data2)
	err := p.WriteFile(fp, src)
	if err != nil {
		t.Fatal(err)
	}

	// read it back to make sure the update worked
	dst := &bytes.Buffer{}
	err = p.ReadFile(fp, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), data2) {
		t.Fatalf("data read back is not correct. Got '%s'", dst.String())
	}
}
