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

func TestKeyAgreementJWKFromDIDDoc(t *testing.T) {
	doc := []byte(`{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security#keyAgreementMethod"
          ],
          "id": "did:io:0xf40ffd36bb3672fe8570dbacb458cc3b9c5b80f3",
          "keyAgreement": [
            "did:io:0xfedfd2594a66ecc582fc005ee8706e72915d7c40#Key-p256-2147483619"
          ],
          "verificationMethod": [
            {
              "id": "did:io:0xfedfd2594a66ecc582fc005ee8706e72915d7c40#Key-p256-2147483619",
              "type": "JsonWebKey2020",
              "controller": "did:io:0xf40ffd36bb3672fe8570dbacb458cc3b9c5b80f3",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "LP0gjxxSJgkw4gj2zqEtqTSFD0747Jvmye5HNvqFfc0",
                "y": "jNojRxyQIB-hRtyT6P95FwJcMAS4NAbOyXBWN3Pmz50",
                "d": "",
                "kty": "EC",
                "kid": "Key-p256-2147483619"
              }
            }
          ]
        }`)
	jwk, err := ioconnect.JWKFromDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(jwk.DID("io"))
	t.Log(jwk.KID("io"))
}

func TestDocJWK(t *testing.T) {
	// doc from env config as server did doc
	// doc == server ka jwk
	// doc := []byte(`{
	//       "@context": [
	//         "https://www.w3.org/ns/did/v1",
	//         "https://w3id.org/security#keyAgreementMethod"
	//       ],
	//       "id": "did:io:0xf40ffd36bb3672fe8570dbacb458cc3b9c5b80f3",
	//       "keyAgreement": [
	//         "did:io:0xfedfd2594a66ecc582fc005ee8706e72915d7c40#Key-p256-2147483619"
	//       ],
	//       "verificationMethod": [
	//         {
	//           "id": "did:io:0xfedfd2594a66ecc582fc005ee8706e72915d7c40#Key-p256-2147483619",
	//           "type": "JsonWebKey2020",
	//           "controller": "did:io:0xf40ffd36bb3672fe8570dbacb458cc3b9c5b80f3",
	//           "publicKeyJwk": {
	//             "crv": "P-256",
	//             "x": "LP0gjxxSJgkw4gj2zqEtqTSFD0747Jvmye5HNvqFfc0",
	//             "y": "jNojRxyQIB-hRtyT6P95FwJcMAS4NAbOyXBWN3Pmz50",
	//             "d": "",
	//             "kty": "EC",
	//             "kid": "Key-p256-2147483619"
	//           }
	//         }
	//       ]
	//     }`)
	doc := []byte(`{
        "@context":     ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#keyAgreementMethod"],
        "id":   "did:io:0xfe4101561ca184d914a14f8b6e37d187fdd7b603",
        "keyAgreement": ["did:io:0x89f06ca9c73a174f7a55d165d4721008eec86311#Key-p256-2147483619"],
        "verificationMethod":   [{
                        "id":   "did:io:0x89f06ca9c73a174f7a55d165d4721008eec86311#Key-p256-2147483619",
                        "type": "JsonWebKey2020",
                        "controller":   "did:io:0xfe4101561ca184d914a14f8b6e37d187fdd7b603",
                        "publicKeyJwk": {
                                "crv":  "P-256",
                                "x":    "b0s89g_Vhea4BgSD0RQITl0KHDTaZ0p53-KCxZNp0mU",
                                "y":    "cf_qciP457RgEOuWF-YElW8zBc6gt9yyIhNzPUmItsU",
                                "kty":  "EC",
                                "kid":  "Key-p256-2147483619"
                        }
                }]
}`)

	serverKAJWK, err := ioconnect.JWKFromDIDDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(serverKAJWK.DID("io")) // ka did
	t.Log(serverKAJWK.KID("io")) // ka kid
	t.Log(serverKAJWK.KeyAgreementDID("io"))
	t.Log(serverKAJWK.KeyAgreementKID("io"))

	clientMasterJWK, err := ioconnect.NewMasterJWK("io")
	if err != nil {
		t.Fatal(err)
	}

	cipher, err := clientMasterJWK.Encrypt("io", []byte("something"), serverKAJWK.KID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	plain, err := serverKAJWK.DecryptBySenderDID2("io", cipher, clientMasterJWK.DID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}
