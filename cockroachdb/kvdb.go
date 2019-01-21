package cockroachdb

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/pkg/errors"
	"zood.xyz/oscar/kvstor"
)

const createKVDB = `CREATE DATABASE IF NOT EXISTS %s`
const createDropBoxesTable = `CREATE TABLE IF NOT EXISTS drop_boxes (
	box_id BYTES PRIMARY KEY,
	pkg BYTES)`
const createPublicIdsTable = `CREATE TABLE IF NOT EXISTS public_ids (
	user_id INT PRIMARY KEY,
	public_id BYTES)`
const createUserIdsTable = `CREATE TABLE IF NOT EXISTS user_ids (
	public_id BYTES PRIMARY KEY,
	user_id INT)`

const (
	kvTableDropBoxes string = "drop_boxes"
	kvTablePublicIDs        = "public_ids"
)

var kvTables = []string{createDropBoxesTable, createPublicIdsTable, createUserIdsTable}

type kvProvider struct {
	db *sql.DB
}

func newKV(connURI, dbName string) (kvstor.Provider, error) {
	if connURI == "" {
		return nil, errors.New("Connection string is empty")
	}
	sqldb, err := sql.Open("postgres", connURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open CockroachDB")
	}
	err = sqldb.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "failed to ping cockroach db")
	}

	_, err = sqldb.Exec(fmt.Sprintf(createKVDB, dbName))
	if err != nil {
		log.Fatal("Failed to create kv database: ", err)
	}

	_, err = sqldb.Exec(fmt.Sprintf("SET database = %s", dbName))
	if err != nil {
		return nil, errors.Wrap(err, "unable to set database")
	}

	// create the kv tables
	for _, createSQL := range kvTables {
		if _, err = sqldb.Exec(createSQL); err != nil {
			log.Fatal("Failed to create kv table:", err)
		}
	}

	return &kvProvider{db: sqldb}, nil
}

func (p kvProvider) DropPackage(pkg []byte, boxID []byte) error {
	if pkg == nil {
		// if it's a package removal, delete the row completely
		const query = `DELETE FROM drop_boxes WHERE box_id=$1`
		_, err := p.db.Exec(query, boxID)
		return err
	}

	const query = `UPSERT INTO drop_boxes (box_id, pkg) VALUES ($1, $2)`
	_, err := p.db.Exec(query, boxID, pkg)
	return err
}

func (p kvProvider) InsertIds(userID int64, pubID []byte) error {
	const q1 = `UPSERT INTO public_ids (user_id, public_id) VALUES ($1, $2)`
	const q2 = `UPSERT INTO user_ids (public_id, user_id) VALUES ($1, $2)`
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(q1, userID, pubID); err != nil {
		return err
	}
	if _, err = tx.Exec(q2, pubID, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (p kvProvider) PickUpPackage(boxID []byte) ([]byte, error) {
	const query = `SELECT pkg FROM drop_boxes WHERE box_id=$1`
	var pkg []byte
	err := p.db.QueryRow(query, boxID).Scan(&pkg)
	switch err {
	case nil:
		return pkg, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (p kvProvider) PublicIDFromUserID(userID int64) ([]byte, error) {
	const query = `SELECT public_id FROM public_ids WHERE user_id=$1`
	var pubID []byte
	err := p.db.QueryRow(query, userID).Scan(&pubID)
	switch err {
	case nil:
		return pubID, nil
	case sql.ErrNoRows:
		return nil, nil
	default:
		return nil, err
	}
}

func (p kvProvider) UserIDFromPublicID(pubID []byte) (int64, error) {
	const query = `SELECT user_id FROM user_ids WHERE public_id=$1`
	var userID sql.NullInt64
	err := p.db.QueryRow(query, pubID).Scan(&userID)
	switch err {
	case nil:
		return userID.Int64, nil
	case sql.ErrNoRows:
		return 0, nil
	default:
		return 0, err
	}
}
