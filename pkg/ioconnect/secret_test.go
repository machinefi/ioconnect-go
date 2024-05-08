package ioconnect_test

import (
	"bytes"
	"testing"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func TestNewJWKSecrets(t *testing.T) {
	secrets := ioconnect.NewJWKSecrets()

	secrets2, err := ioconnect.NewJWKSecretsFromBase64(secrets.String())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(secrets.String())
	t.Logf(secrets2.String())

	bytes1 := secrets[0].Bytes()
	bytes2 := secrets2[0].Bytes()
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("not equal")
	}

	bytes1 = secrets[1].Bytes()
	bytes2 = secrets2[1].Bytes()
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatal("not equal")
	}
}
