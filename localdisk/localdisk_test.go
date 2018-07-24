package localdisk

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pijun.io/oscar/filestor"
)

func provider() filestor.Provider3 {
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

func TestBucketRetrieval(t *testing.T) {
	p := provider()
	name := "test123"
	badName := name + string(os.PathSeparator)
	bkt, err := p.Bucket(badName)
	if err != filestor.ErrInvalidName {
		t.Fatalf("Should have failed with a bad bucket name, but got %v", err)
	}

	bkt, err = p.Bucket(name)
	if err != nil {
		t.Fatal(err)
	}

	exists, err := bkt.Exists()
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("Bucket shouldn't exist yet")
	}

	err = bkt.Create()

}

func TestBucketCreation(t *testing.T) {
	p := provider()
	bkt, _ := p.Bucket("not-created-yet")

	err := bkt.Create()
	if err != nil {
		t.Fatalf("Bucket creation failed: %v", err)
	}

	exists, err := bkt.Exists()
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("Bucket should exist now")
	}
}

func TestObjectCreation(t *testing.T) {
	// just ignore all errors from these first calls, because they get tested elsewhere
	p := provider()
	bkt, _ := p.Bucket("put-objects-here")
	bkt.Create()

	data := []byte("rock a bye baby, on the tree top")
	rdr := bytes.NewReader(data)

	if err := bkt.WriteObject("lyrics.txt", rdr); err != nil {
		t.Fatal(err)
	}

	dst := &bytes.Buffer{}
	if err := bkt.ReadObject("lyrics.txt", dst); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dst.Bytes(), data) {
		t.Fatalf("object did not match after reading it back: Got '%s'", string(dst.Bytes()))
	}
}

func TestObjectExistence(t *testing.T) {
	p := provider()
	bkt, _ := p.Bucket("put-objects-here")
	bkt.Create()

	name := "notes.txt"
	badName := name + string(os.PathSeparator)
	// test it with a bad name
	_, err := bkt.ObjectExists(badName)
	if err != filestor.ErrInvalidName {
		t.Fatalf("Should have failed with an invalid name, but ot %v", err)
	}

	exists, err := bkt.ObjectExists(name)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("This object shouldn't exist yet")
	}

	data := []byte("We're all we need")
	src := bytes.NewReader(data)
	bkt.WriteObject(name, src)
	exists, err = bkt.ObjectExists(name)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("This file should exist now")
	}
}
