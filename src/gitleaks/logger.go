package main

import (
	"runtime"

	"github.com/sirupsen/logrus"
)

var (
	appLogger = newAppLogger()
)

func newAppLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return logger
}

var mem runtime.MemStats

func writeMemStats() {
	runtime.ReadMemStats(&mem)
	appLogger.Infof("MEM stats: HeapAlloc %d / %d byte (total %d byte)",
		mem.HeapAlloc, mem.HeapSys, mem.TotalAlloc) // https://pkg.go.dev/runtime#MemStats
	// mem.HeapAlloc/1024/1024, mem.HeapSys/1024/1024, mem.TotalAlloc/1024/1024)
}
