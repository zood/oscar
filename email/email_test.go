package email

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zood.dev/oscar/base62"
)

func TestIsValid(t *testing.T) {
	testCases := []struct {
		scenario string
		input    string
		errMsg   *string
	}{
		{
			scenario: "empty input",
			errMsg:   new("is empty"),
		},
		{
			scenario: "address too long",
			input:    base62.Rand(255) + "@zood.xyz",
			errMsg:   new("is too long"),
		},
		{
			scenario: "just the local",
			input:    "username",
			errMsg:   new("doesn't have a user and domain"),
		},
		{
			scenario: "missing local",
			input:    "@zood.xyz",
			errMsg:   new("invalid local component"),
		},
		{
			scenario: "invalid domain",
			input:    "local@zood",
			errMsg:   new("invalid domain"),
		},
		{
			scenario: "invalid tld",
			input:    "local@zood.x",
			errMsg:   new("invalid tld"),
		},
		{
			scenario: "valid email ",
			input:    "username@zood.xyz",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.scenario, func(t *testing.T) {
			err := IsValid(tc.input)
			if tc.errMsg != nil {
				require.ErrorContains(t, err, *tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
