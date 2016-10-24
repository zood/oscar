package main

import (
	"net/http"
	"runtime/pprof"
)

func goroutineStacksHandler(w http.ResponseWriter, r *http.Request) {
	pprof.Lookup("goroutine").WriteTo(w, 1)
}
