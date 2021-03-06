package mailgun

import (
	"flag"
	"fmt"
	"testing"
	"time"
)

var apiKeyArg = flag.String("apikey", "", "Mailgun API key")
var domainArg = flag.String("domain", "", "Domain for mailgun api")

func TestSendEmail(t *testing.T) {
	if *apiKeyArg == "" {
		t.Skip("No mailgun api key provided")
	}
	if *domainArg == "" {
		t.Skip("No mailfun domain specified")
	}

	emailer := New(*apiKeyArg, *domainArg)
	emailer.(*mailgun).testMode = true

	now := time.Now().Unix()
	from := fmt.Sprintf("test%d@%s", now, *domainArg)
	to := fmt.Sprintf("fake-recipient-%d@zood.xyz", now)
	subj := fmt.Sprintf("Subject %d", now)
	txtMsg := fmt.Sprintf("Text body: %d https://zood.xyz", now)

	if err := emailer.SendEmail(from, to, subj, txtMsg, nil); err != nil {
		t.Fatal(err)
	}
}
