package main

type contextKey string

const (
	contextUserIDKey                    = contextKey("user_id")
	contextFileStorageProviderKey       = contextKey("file_storage_provider")
	contextKeyValueProviderKey          = contextKey("key_value_provider")
	contextRelationalStorageProviderKey = contextKey("relational_storage_provider")
)
