package email

import (
	"errors"
	"strings"
)

func IsValid(input string) error {
	if input == "" {
		return errors.New("email address is empty")
	}
	if len(input) > 254 {
		return errors.New("email address is too long")
	}
	parts := strings.Split(input, "@")
	if len(parts) != 2 {
		return errors.New("email address doesn't have a user and domain separated by an '@'")
	}
	if parts[0] == "" {
		return errors.New("invalid local component in email")
	}
	domainParts := strings.Split(parts[1], ".")
	if len(domainParts) < 2 {
		return errors.New("invalid domain in email address")
	}
	tld := domainParts[len(domainParts)-1]
	if len(tld) < 2 {
		return errors.New("invalid tld in domain")
	}

	return nil
}
