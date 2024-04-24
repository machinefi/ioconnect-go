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
	t.Logf("server did:io:        %s", server.DIDio())
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
	// doc -> jwk == server ka jwk
	// cipher, err := client.Encrypt("io", []byte("payload"), jwk.KID("io"))
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

func TestDocJWK(t *testing.T) {
	doc := []byte(`{{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security#keyAgreementMethod"
          ],
          "id": "did:io:0xb891f3302899b7b2103936c32ddeff079d2f1e87",
          "authentication": [
            "did:io:0xb891f3302899b7b2103936c32ddeff079d2f1e87#Key-p256-2147483618"
          ],
          "keyAgreement": [
            "did:io:0xab63218ccfa019e6daf62d3a39a126355eddfe69#Key-p256-2147483619"
          ],
          "verificationMethod": [
            {
              "id": "did:io:0xab63218ccfa019e6daf62d3a39a126355eddfe69#Key-p256-2147483619",
              "type": "JsonWebKey2020",
              "controller": "did:io:0xb891f3302899b7b2103936c32ddeff079d2f1e87",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "5O64uLgTtIb0xwX9qnvR3eo2VeEUxMqtSSjmpC6rvRM",
                "y": "8_wJMyz5oDeKaOnoj9lxvl9E07bhB8WsZv_qBFiC7OA",
                "d": "",
                "kty": "EC",
                "kid": "Key-p256-2147483619"
              }
            },
            {
              "id": "did:io:0xb891f3302899b7b2103936c32ddeff079d2f1e87#Key-p256-2147483618",
              "type": "JsonWebKey2020",
              "controller": "did:io:0xb891f3302899b7b2103936c32ddeff079d2f1e87",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "9n5mPtmA9m8pcRV5t8VD6mAjZBwxj3pAVp7TuIWXSDs",
                "y": "ITvZM7ADJlx7sBN1iua4Xdi0-234sjgTiKhTu2Ytvzk",
                "d": "",
                "kty": "EC",
                "kid": "Key-p256-2147483618"
              }
            }
          ]
        }`)

	server, err := ioconnect.JWKFromDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(server.DID("io")) // ka did
	t.Log(server.KID("io")) // ka kid
	t.Log(server.KeyAgreementDID("io"))
	t.Log(server.KeyAgreementKID("io"))

	client, err := ioconnect.NewMasterJWK("io")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := client.Encrypt("io", []byte("something"), server.KeyAgreementKID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	plain, err := server.DecryptBySenderDID("io", cipher, client.DID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}
