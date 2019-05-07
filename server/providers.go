package main

import (
	"context"
	crand "crypto/rand"
	"net/http"
	"testing"

	"zood.xyz/oscar/boltdb"
	"zood.xyz/oscar/filestor"
	"zood.xyz/oscar/kvstor"
	"zood.xyz/oscar/relstor"
	"zood.xyz/oscar/sodium"
	"zood.xyz/oscar/sqlite"
)

type serverProviders struct {
	db      relstor.Provider
	fs      filestor.Provider
	kvs     kvstor.Provider
	symKey  []byte
	keyPair sodium.KeyPair
}

func createTestProviders(t *testing.T) *serverProviders {
	db, err := sqlite.New(sqlite.InMemoryDSN)
	if err != nil {
		t.Fatal(err)
	}
	kvs := boltdb.Temp(t)
	symKey := make([]byte, sodium.SymmetricKeySize)
	crand.Read(symKey)
	keyPair, err := sodium.NewKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return &serverProviders{
		db:      db,
		kvs:     kvs,
		symKey:  symKey,
		keyPair: keyPair,
	}
}

func providersCtx(ctx context.Context) *serverProviders {
	return ctx.Value(contextServerProvidersKey).(*serverProviders)
}

func providersInjector(p *serverProviders, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextServerProvidersKey, p)
		// -- BEGIN TEMP --
		// ctx = context.WithValue(r.Context(), contextFileStorageProviderKey, p.fs)
		// ctx = context.WithValue(ctx, contextRelationalStorageProviderKey, p.db)
		// ctx = context.WithValue(ctx, contextKeyValueProviderKey, p.kvs)
		// -- END TEMP --
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
