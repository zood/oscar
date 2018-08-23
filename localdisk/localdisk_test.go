package localdisk

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"zood.xyz/oscar/filestor"
)

func provider() filestor.Provider {
	root := filepath.Join(os.TempDir(), fmt.Sprintf("%d", time.Now().UnixNano()))
	os.MkdirAll(root, 0755)
	p, _ := New(root)
	return p
}

func TestProviderCreation(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatal("Should have failed with no directory")
	}

	_, err = New(filepath.Join(os.TempDir(), "3920101")) // random name
	if err == nil {
		t.Fatal("Should have failed with a directory that doesn't exist")
	}

	// make a file on disk and try to pass it off as a directory
	fp := filepath.Join(os.TempDir(), fmt.Sprintf("%d", time.Now().UnixNano()))
	f, err := os.Create(fp)
	if err != nil {
		t.Fatalf("Failed to create a file for the dir check: %v", err)
	}
	f.Close()
	_, err = New(fp)
	if err == nil {
		t.Fatal("Should have failed and complained that it's a file")
	}

	p, err := New(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if p == nil {
		t.Fatal("Should have received a valid provider")
	}
}

func TestReadNonExistentObject(t *testing.T) {
	p := provider()
	fp := filepath.Join("somedir", "should-not-exist")

	dst := &bytes.Buffer{}
	err := p.ReadFile(fp, dst)
	if err != filestor.ErrFileNotExist {
		t.Fatalf("Should have received 'file not exist'. Got %v", err)
	}
}

func TestWriteNewFile(t *testing.T) {
	p := provider()
	fp := filepath.Join("anotherdir", "lyrics.txt")

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
	fp := filepath.Join("yetanotherdir", "list.txt")
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
