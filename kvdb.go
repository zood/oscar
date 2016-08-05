package main

import "github.com/boltdb/bolt"

var gKVDB *bolt.DB

func initKVDB(dbPath string) error {
	var err error
	gKVDB, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return err
	}

	return nil
}

func kvdb() *bolt.DB {
	return gKVDB
}
