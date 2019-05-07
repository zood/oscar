package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"zood.dev/oscar/base62"
)

func TestCreateSocketHandler(t *testing.T) {
	providers := createTestProviders(t)

	user, keyPair := createTestUser(t, providers)

	hndlr := providersInjector(providers, createSocketHandler)
	server := httptest.NewServer(hndlr)
	defer server.Close()

	// make sure we get rejected when no token or ticket is provided
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")

	dialer := &websocket.Dialer{}
	_, _, err := dialer.Dial(endpoint, nil)
	if err == nil {
		t.Fatal("The websocket upgrade should have failed")
	}

	// try logging in with an access token
	accessToken := loginTestUser(t, providers, user, keyPair)
	hdrs := make(http.Header)
	hdrs.Set("Sec-Websocket-Protocol", accessToken)
	conn, _, err := dialer.Dial(endpoint, hdrs)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// try logging in with a ticket
	ticket := base62.Rand(ticketLength)
	providers.db.InsertTicket(ticket, user.ID)

	endpoint = "ws" + strings.TrimPrefix(server.URL, "http") + "?ticket=" + ticket
	conn, _, err = dialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}
