package boltdb

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/boltdb/bolt"
	"zood.dev/oscar/kvstor"
)

var userIDsBucketName = []byte("user_ids")
var publicIDsBucketName = []byte("public_ids")
var dropboxesBucketName = []byte("drop_boxes")

type boltdbProvider struct {
	db *bolt.DB
}

// New returns a kvstor.Provider backed by a bolt database written to the
// file specified at dbPath
func New(dbPath string) (kvstor.Provider, error) {
	var err error
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	tx, err := db.Begin(true)
	if err != nil {
		return nil, err
	}
	_, err = tx.CreateBucketIfNotExists(userIDsBucketName)
	if err != nil {
		return nil, fmt.Errorf("Error creating '%s' bucket: %v", userIDsBucketName, err)
	}
	_, err = tx.CreateBucketIfNotExists(publicIDsBucketName)
	if err != nil {
		return nil, fmt.Errorf("Error creating '%s' bucket: %v", publicIDsBucketName, err)
	}
	_, err = tx.CreateBucketIfNotExists(dropboxesBucketName)
	if err != nil {
		return nil, fmt.Errorf("Error creating '%s' bucket: %v", dropboxesBucketName, err)
	}
	err = tx.Commit()
	if err != nil {
		return nil, fmt.Errorf("Error commiting initialiation of kvdb: %v", err)
	}

	return boltdbProvider{db: db}, nil
}

// Temp returns a new database backed by a file in the system temp directory
func Temp(t *testing.T) kvstor.Provider {
	file := filepath.Join(os.TempDir(), fmt.Sprintf("bolt%d.db", time.Now().UnixNano()))
	db, err := New(file)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func (bdp boltdbProvider) DropPackage(pkg []byte, boxID []byte) error {
	err := bdp.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(dropboxesBucketName)
		err := bucket.Put(boxID, pkg)
		return err
	})
	return err
}

func (bdp boltdbProvider) InsertIds(userID int64, pubID []byte) error {
	tx, err := bdp.db.Begin(true)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	userIDBytes := int64ToBytes(userID)
	uidsBucket := tx.Bucket(userIDsBucketName)
	err = uidsBucket.Put(pubID, userIDBytes)
	if err != nil {
		return err
	}

	pubIDsBucket := tx.Bucket(publicIDsBucketName)
	err = pubIDsBucket.Put(userIDBytes, pubID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (bdp boltdbProvider) PickUpPackage(boxID []byte) ([]byte, error) {
	var pkgCopy []byte
	bdp.db.View(func(tx *bolt.Tx) error {
		pkg := tx.Bucket(dropboxesBucketName).Get(boxID)
		// we have to copy the package, because the slice is only
		// valid for the duration of the transaction
		if len(pkg) > 0 {
			pkgCopy = make([]byte, len(pkg))
			copy(pkgCopy, pkg)
		}
		return nil
	})
	return pkgCopy, nil
}

func (bdp boltdbProvider) PublicIDFromUserID(userID int64) ([]byte, error) {
	tx, err := bdp.db.Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()
	return tx.Bucket(publicIDsBucketName).Get(int64ToBytes(userID)), nil
}

func (bdp boltdbProvider) UserIDFromPublicID(pubID []byte) (int64, error) {
	tx, err := bdp.db.Begin(false)
	if err != nil {
		panic(err)
	}
	defer tx.Rollback()

	userIDBytes := tx.Bucket(userIDsBucketName).Get(pubID)
	if len(userIDBytes) == 0 {
		return 0, nil
	}
	return bytesToInt64(userIDBytes)
}
