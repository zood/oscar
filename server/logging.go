package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"zood.dev/oscar/encodable"
)

type callerAddingHook struct{}

func (h callerAddingHook) Run(e *zerolog.Event, level zerolog.Level, _ string) {
	switch level {
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
	default:
		return
	}

	e.Caller(3)
}

func shouldLogDebug() bool {
	return zerolog.GlobalLevel() <= zerolog.DebugLevel
}

func initLogging() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	cw := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "2006-01-02T15:04:05",
	}
	log.Logger = zerolog.New(cw).With().Timestamp().Logger().Hook(callerAddingHook{})
}

func (api httpAPI) enableDebugLoggingHandler(w http.ResponseWriter, _ *http.Request) {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("debug logging ENABLED"))
}

func (api httpAPI) disableDebugLoggingHandler(w http.ResponseWriter, r *http.Request) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("debug logging DISABLED"))
}

func recordLogMessageHandler(w http.ResponseWriter, r *http.Request) {
	postBody := struct {
		UserID    encodable.Bytes `json:"user_id"`
		Timestamp int64           `json:"timestamp"`
		Message   string          `json:"message"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&postBody)
	if err != nil {
		sendBadReq(w, "Failed to decode post body: "+err.Error())
		return
	}

	sendSuccess(w, nil)
}
