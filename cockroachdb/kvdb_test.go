package cockroachdb

import (
	"bytes"
	"sync"
	"testing"

	"zood.xyz/oscar/kvstor"
)

var kvdbSingleton kvstor.Provider
var kvdbOnce sync.Once

func dbKV(t *testing.T) kvstor.Provider {
	var err error
	kvdbOnce.Do(func() {
		kvdbSingleton, err = newKV("postgresql://root@127.0.0.1:26257/oscarkv?sslmode=disable", "oscarkv")
		if err != nil {
			t.Fatal(err)
		}
	})

	if kvdbSingleton == nil {
		t.Fatal("kv db was never initialized")
	}

	return kvdbSingleton
}

func TestPackages(t *testing.T) {
	pkg1 := []byte("this is package 1")
	box1 := []byte("this is box1")

	// box1 should be empty
	pkg, err := dbKV(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg) != 0 {
		t.Fatalf("the package should have been nil")
	}

	err = dbKV(t).DropPackage(pkg1, box1)
	if err != nil {
		t.Fatal(err)
	}

	pkg, err = dbKV(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkg, pkg1) {
		t.Fatal("Bytes did not after trying to pick up package 1")
	}

	// wipe the package in box 1
	err = dbKV(t).DropPackage(nil, box1)
	if err != nil {
		t.Fatal(err)
	}

	// it should be nil now
	pkg, err = dbKV(t).PickUpPackage(box1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkg) != 0 {
		t.Fatal("Box 1 should have been wiped")
	}
}

func TestIDs(t *testing.T) {
	// there should be no IDs at first
	pubID, err := dbKV(t).PublicIDFromUserID(1)
	if err != nil {
		t.Fatal(err)
	}

	if len(pubID) != 0 {
		t.Fatal("Public id should have been nil")
	}

	userID, err := dbKV(t).UserIDFromPublicID([]byte("fake public id"))
	if err != nil {
		t.Fatal(err)
	}
	if userID != 0 {
		t.Fatalf("No user id should have been found. Should be zero value. Got %d", userID)
	}

	// now insert some ids
	aliceID := int64(300)
	alicePubID := []byte("public id made of random data")
	err = dbKV(t).InsertIds(aliceID, alicePubID)
	if err != nil {
		t.Fatal(err)
	}

	// make sure we can retrieve them
	pubID, err = dbKV(t).PublicIDFromUserID(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubID, alicePubID) {
		t.Fatal("alice's public id didn't match")
	}

	userID, err = dbKV(t).UserIDFromPublicID(alicePubID)
	if err != nil {
		t.Fatal(err)
	}
	if userID != aliceID {
		t.Fatalf("Alice's user id (%d) did not match returned value. %d", aliceID, userID)
	}
}
