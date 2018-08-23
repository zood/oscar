package boltdb

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"zood.xyz/oscar/kvstor"
)

var bdb kvstor.Provider
var bdbOnce sync.Once

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func db(t *testing.T) kvstor.Provider {
	var err error
	bdbOnce.Do(func() {
		dbPath := filepath.Join(os.TempDir(), fmt.Sprintf("%d.kvdb", time.Now().Unix()))
		bdb, err = New(dbPath)
		if err != nil {
			t.Fatal(err)
		}
	})

	if bdb == nil {
		t.Fatal("db was never initialized")
	}

	return bdb
}

func TestPackages(t *testing.T) {
	pkg1 := []byte("this is package 1")
	box1 := []byte("this is box1")

	// box1 should be empty
	pkg, err := db(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg) != 0 {
		t.Fatalf("the package should have been nil")
	}

	err = db(t).DropPackage(pkg1, box1)
	if err != nil {
		t.Fatal(err)
	}

	pkg, err = db(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkg, pkg1) {
		t.Fatal("Bytes did not after trying to pick up package 1")
	}

	// wipe the package in box 1
	err = db(t).DropPackage(nil, box1)
	if err != nil {
		t.Fatal(err)
	}

	// it should be nil now
	pkg, err = db(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg) != 0 {
		t.Fatal("Box 1 should have been wiped")
	}
}

func TestIDs(t *testing.T) {
	// there should be no IDs at first
	pubID, err := db(t).PublicIDFromUserID(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(pubID) != 0 {
		t.Fatal("Public id should have been nil")
	}

	userID, err := db(t).UserIDFromPublicID([]byte("fake public id"))
	if err != nil {
		t.Fatal(err)
	}
	if userID != 0 {
		t.Fatalf("No user id should have been found. Should be zero value. Got %d", userID)
	}

	// now insert some ids
	aliceID := int64(300)
	alicePubID := []byte("public id made of random data")
	err = db(t).InsertIds(aliceID, alicePubID)
	if err != nil {
		t.Fatal(err)
	}

	// make sure we can retrieve them
	pubID, err = db(t).PublicIDFromUserID(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubID, alicePubID) {
		t.Fatal("alice's public id didn't match")
	}

	userID, err = db(t).UserIDFromPublicID(alicePubID)
	if err != nil {
		t.Fatal(err)
	}
	if userID != aliceID {
		t.Fatalf("Alice's user id (%d) did not match returned value. %d", aliceID, userID)
	}
}
