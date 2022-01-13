package main

import (
	"runtime"

	"github.com/ca-risken/common/pkg/logging"
)

var (
	appLogger = logging.NewLogger()
	mem       runtime.MemStats
)

func writeMemStats() {
	runtime.ReadMemStats(&mem)
	appLogger.Infof("MEM stats: HeapAlloc %d / %d byte (total %d byte)",
		mem.HeapAlloc, mem.HeapSys, mem.TotalAlloc) // https://pkg.go.dev/runtime#MemStats
	// mem.HeapAlloc/1024/1024, mem.HeapSys/1024/1024, mem.TotalAlloc/1024/1024)
}
