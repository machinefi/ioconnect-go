package main

import (
	"log/slog"
	"os"
)

func main() {
	if err := RunServer(9999, nil); err != nil {
		slog.Error("http server down", "error", err)
		os.Exit(-1)
	}
}
