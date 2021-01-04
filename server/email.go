package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"

	"zood.dev/oscar/smtp"

	"github.com/gorilla/mux"
)

const welcomeEmailTemplate = `Hi,

Thanks for signing up for Zood Location.

To verify your email address, click the link below:
https://www.zood.xyz/verify-email?t={{.Token}}

I hope you enjoy using Zood Location as much as I enjoyed creating it. If you have any comments, questions or suggestions you can reply directly to this email.

Best,
Arash

If you didn't sign up for Zood Location, sorry for the inconvenience. Somebody signed up and mistakenly used your email address. You can click the link below to dissociate your email address from this account:
https://www.zood.xyz/disavow-email?t={{.Token}}
`

const notificationsEmailAddress = "Zood Location <email-verification@notifications.zood.xyz>"

func sendVerificationEmail(token, email string, emailer smtp.SendEmailer) error {
	tmpl, err := template.New("").Parse(welcomeEmailTemplate)
	if err != nil {
		return err
	}
	buf := &bytes.Buffer{}
	tmpl.Execute(buf, struct{ Token string }{Token: token})
	return emailer.SendEmail(notificationsEmailAddress, email, "Zood Location: Email Verification", buf.String(), nil)
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
		return
	}

	db := providersCtx(r.Context()).db
	evtr, err := db.EmailVerificationTokenRecord(body.Token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}
	if evtr == nil {
		sendBadReqCode(w, "Invalid token", errorMissingVerificationToken)
		return
	}

	// add the email to the user, then delete the verification
	err = db.VerifyEmail(evtr.Email, evtr.UserID)
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

	db := providersCtx(r.Context()).db
	err := db.DisavowEmail(token)
	if err != nil {
		sendInternalErr(w, err)
		return
	}

	sendSuccess(w, nil)
}
