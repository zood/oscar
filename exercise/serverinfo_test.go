package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestServerInfo(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, apiRoot+"/server-info", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Incorrect status code: %d", resp.StatusCode)
	}

	obj := struct {
		BuildTime string `json:"build_time"`
		SysKb     int    `json:"sys_kb"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&obj)
	if err != nil {
		t.Fatal(err)
	}
}
