package main

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/filestor"
	"zood.dev/oscar/kvstor"
	"zood.dev/oscar/localdisk"
	"zood.dev/oscar/model"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

type serverProviders struct {
	db      model.Provider
	emailer smtp.SendEmailer
	fs      filestor.Provider
	kvs     kvstor.Provider
	symKey  []byte
	keyPair sodium.KeyPair
}

func (sp *serverProviders) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextServerProvidersKey, sp)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func createTestProviders(t *testing.T) *serverProviders {
	t.Helper()

	db := sqlite.NewMockDB(t)

	kvs := boltdb.Temp(t)
	symKey := make([]byte, sodium.SymmetricKeySize)
	crand.Read(symKey)
	keyPair, err := sodium.NewKeyPair()
	require.NoError(t, err)

	tmpDir := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d", t.Name(), time.Now().Unix()))
	err = os.MkdirAll(tmpDir, 0755)
	require.NoError(t, err)
	fstor, err := localdisk.New(tmpDir)
	require.NoError(t, err)

	return &serverProviders{
		db:      db,
		emailer: smtp.NewMockSendEmailer(),
		kvs:     kvs,
		symKey:  symKey,
		keyPair: keyPair,
		fs:      fstor,
	}
}

func providersCtx(ctx context.Context) *serverProviders {
	return ctx.Value(contextServerProvidersKey).(*serverProviders)
}

func providersInjector(p *serverProviders, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextServerProvidersKey, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
