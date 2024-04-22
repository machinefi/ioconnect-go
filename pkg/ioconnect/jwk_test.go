package ioconnect_test

import (
	"encoding/json"
	"testing"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func TestNewJWK(t *testing.T) {
	master, err := ioconnect.NewMasterJWK("io", "key")
	if err != nil {
		t.Fatal(err)
	}
	// master.PrintFields()

	did := master.DID("io")
	t.Logf("did:io: %s", did)
	kid := master.KID("io")
	t.Logf("did:io#key: %s", kid)

	typ := master.Type()
	t.Logf("%d: %s", typ, typ)

	ec, ok := master.Param().(*ioconnect.EC)
	if !ok {
		t.Fatal("unexpected param")
	}
	t.Logf("crv: %s", ec.Crv())
	t.Logf("x:   %s", ec.X())
	t.Logf("y:   %s", ec.Y())
	t.Logf("sk:  %s", ec.EccPrivateKey())

	doc, err := master.DIDDoc("io")
	if err != nil {
		t.Fatal(err)
	}
	serializedDoc, _ := json.MarshalIndent(doc, "", "  ")
	t.Logf(string(serializedDoc))

	did = master.DID("key")
	t.Logf("did:key: %s", did)
	kid = master.KID("key")
	t.Logf("did:key#key: %s", kid)

	did = master.DID("unsupported")
	t.Logf("did:unsupported: %s", did)
	kid = master.KID("unsupported")
	t.Logf("did:unsupported#key: %s", kid)

	client, err := ioconnect.NewMasterJWK("io", "key")
	if err != nil {
		t.Fatal(err)
	}

	token, err := master.SignToken("io", client)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

	jwe, err := client.Encrypt("io", []byte("payload"), master.KID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(jwe)
}
