package ioconnect_test

import (
	"encoding/json"
	"testing"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func TestNewJWK(t *testing.T) {
	// server:
	server, err := ioconnect.NewMasterJWK("io", "key")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("server did:io:        %s", server.DID("io"))
	t.Logf("server did:io#key:    %s", server.KID("io"))
	t.Logf("server ka did:io:     %s", server.KeyAgreementDID("io"))
	t.Logf("server ka did:io#key: %s", server.KeyAgreementKID("io"))

	// client
	client, err := ioconnect.NewMasterJWK("io", "key")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("client did:io:        %s", client.DID("io"))
	t.Logf("client did:io#key:    %s", client.KID("io"))
	t.Logf("client ka did:io:     %s", client.KeyAgreementDID("io"))
	t.Logf("client ka did:io#key: %s", client.KeyAgreementKID("io"))

	// generate client did doc
	clientdoc, err := client.DIDDoc("io")
	if err != nil {
		t.Fatal(err)
	}
	clientdoccontent, _ := json.MarshalIndent(clientdoc, "", "  ")
	t.Logf(string(clientdoccontent))

	// mock
	// device register: did + diddoc -> device portal(uuz)
	// device jwk en/decrypt

	// sprout: did -> portal -> did doc(serialized) ? @uuz
	// did doc -> jwk
	// jwk decrypt encrypt

	// sign token for client
	// client registered to portal
	token, err := server.SignToken("io", client)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

	// verify token
	clientdid, err := server.VerifyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(clientdid)

	// did comm client encrypt
	// client.encrypt(plain, server ka id)=>cipher
	// server.decrypt(cipher, client ka id)=>plain

	// device 1
	cipher, err := client.Encrypt("io", []byte("payload"), server.KeyAgreementKID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	// _, _ = server.KeyAgreement("io")

	// DID -> DOC doc->jwk
	// server 1
	plain, err := server.Decrypt("io", cipher, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))

	plain, err = server.DecryptBySenderDID("io", cipher, client.DID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}
