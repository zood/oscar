package main

import (
	"fmt"

	"github.com/boltdb/bolt"
)

var gKVDB *bolt.DB
var userIDsBucketName = []byte("user_ids")
var publicIDsBucketName = []byte("public_ids")
var dropboxesBucketName = []byte("drop_boxes")

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
		return fmt.Errorf("Error creating '%s' bucket: %v", userIDsBucketName, err)
	}
	_, err = tx.CreateBucketIfNotExists(publicIDsBucketName)
	if err != nil {
		return fmt.Errorf("Error creating '%s' bucket: %v", publicIDsBucketName, err)
	}
	_, err = tx.CreateBucketIfNotExists(dropboxesBucketName)
	if err != nil {
		return fmt.Errorf("Error creating '%s' bucket: %v", dropboxesBucketName, err)
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
