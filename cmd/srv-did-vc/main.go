package main

import (
	"log"
	"log/slog"
	"os"

	"github.com/pkg/errors"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

var config = &struct {
	JWKSecrets ioconnect.JWKSecrets `env:"SRV_DID_VC__JWKSecrets"`
}{}

func init() {
}

func init() {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)
}

func init() {
	k := "SRV_DID_VC__JWKSecrets"
	v := os.Getenv(k)

	if v != "" {
		log.Printf("secret from env: %s", v)
		if err := config.JWKSecrets.UnmarshalText([]byte(v)); err != nil {
			panic(errors.Errorf("invalid jwk secrets from evn: %s", v))
		}
		return
	}

	config.JWKSecrets = ioconnect.NewJWKSecrets()
	log.Printf("volatile secret: %s", config.JWKSecrets.String())
}

func main() {
	if err := RunServer(9999, config.JWKSecrets); err != nil {
		slog.Error("http server down", "error", err)
		os.Exit(-1)
	}
}
