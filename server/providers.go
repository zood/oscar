package main

import (
	"context"
	crand "crypto/rand"
	"net/http"
	"testing"

	"zood.dev/oscar/boltdb"
	"zood.dev/oscar/filestor"
	"zood.dev/oscar/kvstor"
	"zood.dev/oscar/relstor"
	"zood.dev/oscar/smtp"
	"zood.dev/oscar/sodium"
	"zood.dev/oscar/sqlite"
)

type serverProviders struct {
	db      relstor.Provider
	emailer smtp.SendEmailer
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
		emailer: smtp.NewMockSendEmailer(),
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
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
