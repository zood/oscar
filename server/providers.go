package main

import (
	"context"
	"net/http"

	"zood.xyz/oscar/filestor"
	"zood.xyz/oscar/kvstor"
	"zood.xyz/oscar/relstor"
)

func database(ctx context.Context) relstor.Provider {
	return ctx.Value(contextRelationalStorageProviderKey).(relstor.Provider)
}

func fileStorageProvider(ctx context.Context) filestor.Provider {
	return ctx.Value(contextFileStorageProviderKey).(filestor.Provider)
}

func keyValueStorage(ctx context.Context) kvstor.Provider {
	return ctx.Value(contextKeyValueProviderKey).(kvstor.Provider)
}

func providersInjector(fs filestor.Provider, rs relstor.Provider, kv kvstor.Provider, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), contextFileStorageProviderKey, fs)
		ctx = context.WithValue(ctx, contextRelationalStorageProviderKey, rs)
		ctx = context.WithValue(ctx, contextKeyValueProviderKey, kv)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
