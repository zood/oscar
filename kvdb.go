package main

import (
	"fmt"

	"github.com/boltdb/bolt"
)

var gKVDB *bolt.DB
var userIDsBucketName = []byte("user_ids")

func initKVDB(dbPath string) error {
	var err error
	gKVDB, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}
	tx, err := gKVDB.Begin(true)
	if err != nil {
		return err
	}
	_, err = tx.CreateBucketIfNotExists(userIDsBucketName)
	if err != nil {
		return fmt.Errorf("Error creating '%s' bucket: %v", string(userIDsBucketName), err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("Error commiting initialiation of kvdb: %v", err)
	}

	return nil
}

func kvdb() *bolt.DB {
	return gKVDB
}
