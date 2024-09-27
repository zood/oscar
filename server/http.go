package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"

	"firebase.google.com/go/v4/messaging"
	"github.com/rs/zerolog/log"
	"zood.dev/oscar/kvstor"
	"zood.dev/oscar/model"
)

type httpAPI struct {
	db  model.Provider
	fcm *messaging.Client
	kvs kvstor.Provider
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if shouldLogDebug() {
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

		next.ServeHTTP(w, r)
	})
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	sendErr(w, "Not an endpoint", http.StatusNotFound, errorNotAnEndpoint)
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
		struct {
			Msg  string  `json:"error_message"`
			Code ErrCode `json:"error_code"`
		}{Msg: msg, Code: apiCode},
		httpCode)
}

func sendBadReqCode(w http.ResponseWriter, msg string, apiCode ErrCode) {
	sendErr(w, msg, http.StatusBadRequest, apiCode)
}

func sendBadReq(w http.ResponseWriter, msg string) {
	sendBadReqCode(w, msg, errorBadRequest)
}

func sendInternalErr(w http.ResponseWriter, err error) {
	sendErr(w, "Internal server error", http.StatusInternalServerError, errorInternal)

	if err != nil {
		_, file, line, ok := runtime.Caller(1)
		if !ok {
			file = "???"
			line = 0
		}
		file = filepath.Base(file)
		log.Info().Str("file", file).Int("line", line).Err(err).Msg("internal server error")
	}
}

func sendNotFound(w http.ResponseWriter, msg string, apiCode ErrCode) {
	sendErr(w, msg, http.StatusNotFound, apiCode)
}

func sendSuccess(w http.ResponseWriter, response interface{}) {
	if response == nil {
		response = struct{}{}
	}

	sendResponse(w, response, http.StatusOK)
}
