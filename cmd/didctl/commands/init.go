package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

var jwk *ioconnect.JWK

func init() {
	configdir := filepath.Join(os.Getenv("HOME"), ".config/didctl")

	if err := os.MkdirAll(configdir, 0700); err != nil {
		panic(errors.Wrap(err, "failed to create config dir"))
	}
	filename := filepath.Join(configdir, "secret")

	var err error

	secret, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("failed to read secret content from %s, try to create new secret\n", filename)
		goto NewSecret
	}
	jwk, err = ioconnect.NewJWKBySecretBase64(string(secret))
	if err != nil {
		fmt.Printf("invalid secret content read from %s, try to create new secret\n", filename)
		goto NewSecret
	}
	return

NewSecret:
	jwk, err = ioconnect.NewJWK()
	if err != nil {
		panic(errors.Wrap(err, "failed to new jwk"))
	}
	content := jwk.Export().String()
	if err = os.WriteFile(filename, []byte(content), 0660); err != nil {
		panic(errors.Wrap(err, "failed to write config"))
	}
	fmt.Printf("initialize jwk config success\n")
}

func GlobalKey() *ioconnect.JWK {
	return jwk
}
