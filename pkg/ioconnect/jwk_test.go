package ioconnect_test

import (
	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
	"testing"
)

func TestNewJWK(t *testing.T) {
	master, err := ioconnect.NewMasterJWK("io", "key")
	if err != nil {
		t.Fatal(err)
	}
	did := master.DID("io")
	t.Logf("did:io: %s", did)
	kid := master.KID("io")
	t.Logf("did:io#key: %s", kid)

	did = master.DID("key")
	t.Logf("did:key: %s", did)
	kid = master.KID("key")
	t.Logf("did:key#key: %s", kid)

	did = master.DID("unsupported")
	t.Logf("did:unsupported: %s", did)
	kid = master.KID("unsupported")
	t.Logf("did:unsupported#key: %s", kid)
}
