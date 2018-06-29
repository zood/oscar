package main

import (
	"os"
	"testing"
)

// usernames of users created throughout these tests
var createdUsers = make([]string, 0)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
