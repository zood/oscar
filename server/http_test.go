package main

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/localdisk"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

func testHTTPAPI(t *testing.T) httpAPI {
	t.Helper()

	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d", t.Name(), time.Now().Unix()))
	err := os.MkdirAll(tmpDir, 0o755)
	require.NoError(t, err)
	fstor, err := localdisk.New(tmpDir)
	require.NoError(t, err)

	symKey := make([]byte, sodium.SymmetricKeySize)
	crand.Read(symKey)

	keyPair, err := sodium.NewKeyPair()
	require.NoError(t, err)

	return httpAPI{
		db:      sqlite.NewMockDB(t),
		emailer: smtp.NewMockSendEmailer(),
		fs:      fstor,
		keyPair: keyPair,
		kvs:     boltdb.Temp(t),
		symKey:  symKey,
	}
}
