package main

type contextKey string

const (
	contextUserIDKey          = contextKey("user_id")
	contextServerProvidersKey = contextKey("server_providers")
)
