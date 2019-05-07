package smtp

// SendEmailer defines an interface a backend can provide for sending an email
type SendEmailer interface {
	SendEmail(from string, to string, subj string, textMsg string, htmlMsg *string) error
}

// MockSendEmailer is useful for unit tests
type MockSendEmailer struct {
	SentEmail bool
}

// SendEmail fulfills the SendEmailer interface
func (m *MockSendEmailer) SendEmail(from string, to string, subj string, textMsg string, htmlMsg *string) error {
	m.SentEmail = true
	return nil
}

// NewMockSendEmailer returns a SendEmailer that doesn't do anything
func NewMockSendEmailer() *MockSendEmailer {
	return &MockSendEmailer{}
}
