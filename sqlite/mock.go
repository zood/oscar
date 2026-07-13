package sqlite

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func NewMockDB(t *testing.T) DB {
	t.Helper()

	db, err := New(InMemoryDSN)
	require.NoError(t, err)
	return *db
}
