package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"

	"zood.xyz/oscar/mailgun"

	"github.com/gorilla/mux"
)

const welcomeEmailTemplate = `Hi,

Thanks for signing up for Zood Location.

To verify your email address, click the link below:
https://emails.zood.xyz/verify-email?t={{.Token}}

We hope you enjoy using Zood Location as much we enjoyed creating it.

Best,
The Zood Location Team

If you didn't sign up for Zood Location, sorry for the inconvenience. Somebody signed up and mistakenly used your email address. You can click the link below to remove your email address from this account:
https://emails.zood.xyz/disavow-email?t={{.Token}}
`

const notificationsEmailAddress = "Zood Location <noreply@notifications.zood.xyz>"

func sendVerificationEmail(token, email string) error {
	tmpl, err := template.New("").Parse(welcomeEmailTemplate)
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	tmpl.Execute(buf, struct{ Token string }{Token: token})
	return mailgun.SendEmail(notificationsEmailAddress, email, "Zood Location: Email Verification", buf.String(), nil)
}

// verifyEmailHandler handles POST /email-verifications
func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Token string `json:"token"`
	}{}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		sendBadReq(w, "unable to parse POST body")
		return
	}

	if body.Token == "" {
		sendBadReqCode(w, "Missing verification token", errorBadRequest)
	}

	evtr, err := rs.EmailVerificationTokenRecord(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if evtr == nil {
		sendBadReqCode(w, "Invalid token", errorMissingVerificationToken)
		return
	}

	// add the email to the user, then delete the verification
	err = rs.VerifyEmail(evtr.Email, evtr.UserID)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}

// disavowEmailHandler handles DELETE /email-verifications
func disavowEmailHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	if token == "" {
		sendBadReqCode(w, "Invalid token", errorMissingVerificationToken)
		return
	}

	err := rs.DisavowEmail(token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
