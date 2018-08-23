package gcs

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zood.xyz/oscar/filestor"
)

var testDir string

func provider() filestor.Provider {
	p, err := New("/home/arash/coding/pijun_env/gcp-credentials.json", "dev-api-pijun-io")
	if err != nil {
		panic(err)
	}
	return p
}

func TestMain(m *testing.M) {
	testDir = fmt.Sprintf("unittest-%d", time.Now().UnixNano())

	// run the tests
	os.Exit(m.Run())
}

func TestProviderCreation(t *testing.T) {
	_, err := New("", "")
	if err == nil {
		t.Fatalf("Should be error when no credentials are provided. Got %v", err)
	}
	_, err = New("/home/arash/coding/pijun_env/gcp-credentials.json", "")
	if err == nil {
		t.Fatalf("Should be error when no bucket name is provided. Got %v", err)
	}

	p, err := New("/home/arash/coding/pijun_env/gcp-credentials.json", "dev-api-pijun-io")
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestReadNonExistentObject(t *testing.T) {
	p := provider()
	fp := filepath.Join(testDir, "should-not-exist")

	dst := &bytes.Buffer{}
	err := p.ReadFile(fp, dst)
	if err != filestor.ErrFileNotExist {
		t.Fatalf("Should have received 'file not exist'. Got %v", err)
	}
}

func TestWriteNewFile(t *testing.T) {
	p := provider()
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
		t.Fatalf("data read back is not correct. Got '%s'", string(dst.Bytes()))
	}
}

func TestUpdateFile(t *testing.T) {
	p := provider()
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
		t.Fatalf("data read back is not correct. Got '%s'", string(dst.Bytes()))
	}
}
