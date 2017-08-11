package main

import (
	"net/http"
	"runtime"
	"runtime/pprof"
)

// ServerBuildTime is set via the linker at build time
var ServerBuildTime string

func goroutineStacksHandler(w http.ResponseWriter, r *http.Request) {
	pprof.Lookup("goroutine").WriteTo(w, 1)
}

func serverInfoHandler(w http.ResponseWriter, r *http.Request) {
	ms := &runtime.MemStats{}
	runtime.ReadMemStats(ms)

	info := map[string]interface{}{
		"build_time": ServerBuildTime,
		"sys_kb":     ms.Sys / 1024,
	}

	sendSuccess(w, info)
}
