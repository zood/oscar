package sqlite

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/model"
)

func NewMockDB(t *testing.T) model.Provider {
	t.Helper()

	db, err := New(InMemoryDSN)
	require.NoError(t, err)
	return db
}
