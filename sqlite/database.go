package sqlite

import "database/sql"

// Databaser provides access to an underlying database
type Databaser interface {
	Database() *sql.DB
}
