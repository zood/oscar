package main

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

var gSQLDatabase *sql.DB
var gSQLXDatabase *sqlx.DB

func initDB(sqlDSN string) error {
	if sqlDSN == "" {
		return errors.New("sql dsn is empty")
	}
	var err error
	gSQLDatabase, err = sql.Open("mysql", sqlDSN)
	if err != nil {
		return err
	}
	// test our SQL connection with a ping
	err = gSQLDatabase.Ping()
	if err != nil {
		return fmt.Errorf("ping to db failed - %v", err)
	}
	gSQLDatabase.SetMaxOpenConns(100)
	gSQLDatabase.SetMaxIdleConns(30)

	gSQLXDatabase = sqlx.NewDb(gSQLDatabase, "mysql")

	return nil
}

func db() *sqlx.DB {
	return gSQLXDatabase
}
