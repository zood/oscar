package smtp

// SendEmailFunc is function definition a backend can provide for sending an email
type SendEmailFunc func(from string, to string, subj string, textMsg string, htmlMsg *string) error

// SendEmailer defines an interface a backend can provide for sending an email
type SendEmailer interface {
	SendEmail(from string, to string, subj string, textMsg string, htmlMsg *string) error
}

// MockSendEmailFunc returns a SendEmailFunc that does nothing, and never returns an error
func MockSendEmailFunc() SendEmailFunc {
	return func(from string, to string, subj string, textMsg string, htmlMsg *string) error {
		return nil
	}
}
