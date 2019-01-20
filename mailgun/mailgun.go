package mailgun

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// APIKey is the secret string used for authentication with the mailgun api
var APIKey string

// Domain is the domain from which your email will be sent
var Domain string

// TestMode determines whether messages will actually be sent by the API
var TestMode = false

// Errors that are returned by this mailgun api
var (
	ErrAPIKeyNotSet = errors.New("the mailgun api key has not been set")
	ErrDomainNotSet = errors.New("the sending domain has not been set")
)

// SendEmail sends an email message
func SendEmail(from string, to string, subj string, textMsg string, htmlMsg *string) error {
	if APIKey == "" {
		return ErrAPIKeyNotSet
	}
	if Domain == "" {
		return ErrDomainNotSet
	}

	vals := url.Values{}
	vals.Set("from", from)
	vals.Set("to", to)
	vals.Set("subject", subj)
	vals.Set("text", textMsg)
	if htmlMsg != nil {
		vals.Set("html", *htmlMsg)
	}
	if TestMode {
		vals.Set("o:testmode", "true")
	}

	req, _ := http.NewRequest(
		"POST",
		fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", Domain),
		strings.NewReader(vals.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", APIKey)
	client := http.Client{}

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			buf, err := ioutil.ReadAll(resp.Body)
			if err == nil {
				return fmt.Errorf("mailgun non-OK response - %s", buf)
			}
			return fmt.Errorf("unable to read mailgun response body on failure - %v", err.Error())
		}
		return nil
	}
	return err
}
