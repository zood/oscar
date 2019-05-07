package mailgun

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"zood.dev/oscar/smtp"
)

type mailgun struct {
	apiKey   string
	domain   string
	testMode bool
}

// New returns a smtp.SendEmailer backed by mailgun
func New(apiKey, domain string) smtp.SendEmailer {
	return &mailgun{
		apiKey: apiKey,
		domain: domain,
	}
}

func (mg *mailgun) SendEmail(from string, to string, subj string, textMsg string, htmlMsg *string) error {
	vals := url.Values{}
	vals.Set("from", from)
	vals.Set("to", to)
	vals.Set("subject", subj)
	vals.Set("text", textMsg)
	if htmlMsg != nil {
		vals.Set("html", *htmlMsg)
	}
	if mg.testMode {
		vals.Set("o:testmode", "true")
	}

	req, _ := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("https://api.mailgun.net/v3/%s/messages", mg.domain),
		strings.NewReader(vals.Encode()))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", mg.apiKey)
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
