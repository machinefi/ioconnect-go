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

	serverdoc, err := server.DIDDoc("io")
	if err != nil {
		t.Fatal(err)
	}
	serverdoccontent, _ := json.MarshalIndent(serverdoc, "", "  ")
	t.Logf(string(serverdoccontent))

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

	// server doc -> server JWK(server2)
	// cipher, err := client.Encrypt("io", []byte("payload"), server2.KeyAgreementKID("io"))

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

	// plain, err = server.DecryptBySenderDID("io", cipher, client.DID("io"))
	plain, err = server.DecryptBySenderDID("io", cipher, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}

func TestKeyAgreementJWKFromDIDDoc(t *testing.T) {
	doc := []byte(`{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security#keyAgreementMethod"
          ],
          "id": "did:io:0x29a57614d3dd201596898c9e137e5c7f38f23b0a",
          "keyAgreement": [
            "did:io:0xe12017b92096b0737097ce4f41a1641ce0d2de9c#Key-p256-2147483619"
          ],
          "verificationMethod": [
            {
              "id": "did:io:0xe12017b92096b0737097ce4f41a1641ce0d2de9c#Key-p256-2147483619",
              "type": "JsonWebKey2020",
              "controller": "did:io:0x29a57614d3dd201596898c9e137e5c7f38f23b0a",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "gpnQitUBlt7_A7--4EIBzn82BITS51RPstCMe2GfH1c",
                "y": "8lX_FgL5VPuoDfJtvwVTwWHiVF3Q7jaoVlAFISQ_ctI",
                "d": "",
                "kty": "EC",
                "kid": "Key-p256-2147483618"
              }
            }
          ]
        }`)
	jwk, err := ioconnect.KeyAgreementJWKFromDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(jwk.DID("io"))
	t.Log(jwk.KID("io"))
}
