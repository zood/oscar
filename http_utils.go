package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
)

type restFunc struct {
	f http.HandlerFunc
}

func (rf *restFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if Debug {
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, r.RemoteAddr)
	}

	defer func() {
		if r := recover(); r != nil {
			s := make([]byte, 2048)
			numBytes := runtime.Stack(s, false)
			stack := s[:numBytes]
			err := fmt.Errorf("recovered - %v\n%s", r, string(stack))
			sendInternalErr(w, err)
		}
	}()

	rf.f(w, r)
}

// NewRESTFunc ...
func NewRESTFunc(f func(http.ResponseWriter, *http.Request)) http.Handler {
	return &restFunc{f: f}
}

func sendResponse(w http.ResponseWriter, response interface{}, httpCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpCode)

	enc := json.NewEncoder(w)
	err := enc.Encode(response)
	if err != nil {
		panic(err)
	}
}

func sendErr(w http.ResponseWriter, msg string, httpCode int, apiCode ErrCode) {
	sendResponse(
		w,
		map[string]interface{}{
			"error_message": msg,
			"error_code":    apiCode,
		},
		httpCode)
}

func sendBadReqCode(w http.ResponseWriter, msg string, apiCode ErrCode) {
	sendErr(w, msg, http.StatusBadRequest, apiCode)
}

func sendBadReq(w http.ResponseWriter, msg string) {
	sendBadReqCode(w, msg, ErrorBadRequest)
}

func sendInternalErr(w http.ResponseWriter, err error) {
	sendErr(w, "Internal server error", http.StatusInternalServerError, ErrorInternal)

	if err != nil {
		_, file, line, ok := runtime.Caller(1)
		if !ok {
			file = "???"
			line = 0
		}
		file = filepath.Base(file)
		log.Printf("%s:%d %v", file, line, err)
	}
}

func sendSuccess(w http.ResponseWriter, response interface{}) {
	if response == nil {
		response = map[string]interface{}{}
	}

	sendResponse(w, response, http.StatusOK)
}
