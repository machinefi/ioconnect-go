package ioconnect_test

import (
	"encoding/json"
	"testing"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func TestNewJWK(t *testing.T) {
	t.Logf("server jwk initial =================")
	server, err := ioconnect.NewJWK()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()

	t.Logf("server did:io:        %s", server.DID())
	t.Logf("server did:io#key:    %s", server.KID())
	t.Logf("server ka did:io:     %s", server.KeyAgreementDID())
	t.Logf("server ka did:io#key: %s", server.KeyAgreementKID())
	secrets := server.Export()
	t.Logf("server secret:        %s", secrets.String())

	serverdoc, _ := json.Marshal(server.Doc())
	t.Logf(string(serverdoc))

	t.Logf("client jwk initial =================")
	client, err := ioconnect.NewJWK()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()

	t.Logf("client did:io:        %s", client.DID())
	t.Logf("client did:io#key:    %s", client.KID())
	t.Logf("client ka did:io:     %s", client.KeyAgreementDID())
	t.Logf("client ka did:io#key: %s", client.KeyAgreementKID())
	secrets = client.Export()
	t.Logf("client secret:        %s", secrets.String())

	clientdoc, _ := json.Marshal(client.Doc())
	t.Logf(string(clientdoc))

	t.Log("request sign token =================")
	token, err := server.SignToken(client.DID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)

	t.Log("request verify token ===============")
	clientdid, err := server.VerifyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(clientdid)

	t.Log("client encrypt payload =============")
	cipher, err := client.Encrypt([]byte("payload"), server.KeyAgreementKID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	t.Log("server decrypt by client did =======")
	plain, err := server.Decrypt(cipher, client.DID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}

func TestNewJWKBySecret(t *testing.T) {
	server, err := ioconnect.NewJWKBySecretBase64("BhogQWRIeGNPOGVSOQI/CmseOjINHmMMUHcCKBUrPhJYWVd3AS1MQ3JmN3UpJH87J30vbDJBDBpaXXEmEjY6aw==")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()

	t.Logf("server did:io:        %s", server.DID())
	t.Logf("server did:io#key:    %s", server.KID())
	t.Logf("server ka did:io:     %s", server.KeyAgreementDID())
	t.Logf("server ka did:io#key: %s", server.KeyAgreementKID())

	clientdid := "did:io:0x77875a13b175b37e32dac76b9b6873d6beadd134"
	cipher := []byte(`{"ciphertext":"bEEYX8RtzQ","protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6aW86MHg3Nzg3NWExM2IxNzViMzdlMzJkYWM3NmI5YjY4NzNkNmJlYWRkMTM0IiwiYXB1IjoiWkdsa09tbHZPakI0TnpjNE56VmhNVE5pTVRjMVlqTTNaVE15WkdGak56WmlPV0kyT0RjelpEWmlaV0ZrWkRFek5BIiwiYXB2IjoieFg3RWdpME16d2FDak8wNUJKX1ExTnFkMWVXcXUxeW1JS05oZEVvSjlGayIsImVwayI6eyJjcnYiOiJQLTI1NiIsIngiOiJRTHVWUE1ZdG9qSHlXODVpRzAtRVlsRUs0OENXQWFoWTJucER5azZCblBrIiwieSI6IjBjT3plY0JUeWRGZFgtZ2lRR2tRSzl2cDRib0J1aW9zSlZoVExOVnY3c3MiLCJrdHkiOiJFQyIsImtpZCI6IktleS1wMjU2LTIxNDc0ODM2MjEifX0","recipients":[{"header":{"kid":"did:io:0x83b6d8fb81cb74f3169c79d97ecdffefc94ef98a#Key-p256-2147483617"},"encrypted_key":"kbQgbMXKi7Sy-kTzp0HSU2mM3zhhoKTQUphm3uAXlMkFnvroadvF4_RJPq2Iv7dB"}],"tag":"WpfSapPskCpE-KUrSPDOwg","iv":"TmfJpljLYpB04iZwQw"}`)

	plain, err := server.Decrypt(cipher, clientdid)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))

	serverdoc := server.Doc()
	serverdoccontent, _ := json.Marshal(serverdoc)
	t.Log(string(serverdoccontent))
}

func TestNewJWKFromDoc(t *testing.T) {
	doc := []byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security#keyAgreementMethod"],"id":"did:io:0xcf0aca7ec91bc9de72dc8fd93a3646ebf193bec0","authentication":["did:io:0xcf0aca7ec91bc9de72dc8fd93a3646ebf193bec0#Key-p256-2147483616"],"keyAgreement":["did:io:0x0a24b85ce86ce8bafaed79f40c90c6ad817f3a79#Key-p256-2147483617"],"verificationMethod":[{"id":"did:io:0x0a24b85ce86ce8bafaed79f40c90c6ad817f3a79#Key-p256-2147483617","type":"JsonWebKey2020","controller":"did:io:0xcf0aca7ec91bc9de72dc8fd93a3646ebf193bec0","publicKeyJwk":{"crv":"P-256","x":"avDyuSpJ8-lxyck8h_ud7tTNHbcyj2COpTmauFlLfdY","y":"Qi5kKMusO9r5Hj4RVt8qVFQ_ZW_Mhwbd4Si7HEJ2u9s","d":"","kty":"EC","kid":"Key-p256-2147483617"}},{"id":"did:io:0xcf0aca7ec91bc9de72dc8fd93a3646ebf193bec0#Key-p256-2147483616","type":"JsonWebKey2020","controller":"did:io:0xcf0aca7ec91bc9de72dc8fd93a3646ebf193bec0","publicKeyJwk":{"crv":"P-256","x":"XPC_AmYO-gwFdsoMrTQ-JmkFKz2DBGg93B7yrX6oO50","y":"jBhhseXq2FXtq9Ru9Lpnlvkb35AGKAnzjmfoO_rOEas","d":"","kty":"EC","kid":"Key-p256-2147483616"}}]}`)

	key, err := ioconnect.NewJWKFromDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	t.Logf("did:io:        %s", key.DID())
	t.Logf("did:io#key:    %s", key.KID())
	t.Logf("ka did:io:     %s", key.KeyAgreementDID())
	t.Logf("ka did:io#key: %s", key.KeyAgreementKID())

	clientdid := "did:io:0x0e6fadf1cf8cd1dedd296541fcd2e27c5d36e269"
	cipher := []byte(`{"{"ciphertext":"qqU0A5bSBg","protected":"eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLWVuY3J5cHRlZCtqc29uIiwiYWxnIjoiRUNESC0xUFUrQTI1NktXIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsInNraWQiOiJkaWQ6aW86MHgwZTZmYWRmMWNmOGNkMWRlZGQyOTY1NDFmY2QyZTI3YzVkMzZlMjY5IiwiYXB1IjoiWkdsa09tbHZPakI0TUdVMlptRmtaakZqWmpoalpERmtaV1JrTWprMk5UUXhabU5rTW1VeU4yTTFaRE0yWlRJMk9RIiwiYXB2IjoiQTd3UVM0Z01IZHFBaU85blZELVZkcGFhNllQaFN4aDBEYmhlVnJ2cGlHdyIsImVwayI6eyJjcnYiOiJQLTI1NiIsIngiOiJNZW9QUDFIVDlXcUtJcE12UUtSZVBfeXlnOGJHbnh5c1BTMk1YanBqVlIwIiwieSI6ImpXRjZhYVB0MnNSanhqUklCT3FFMWFzRVE2Z05fOTB4Vk5LX2JCZWFJc2ciLCJrdHkiOiJFQyIsImtpZCI6IktleS1wMjU2LTIxNDc0ODM2MjEifX0","recipients":[{"header":{"kid":"did:io:0x0a24b85ce86ce8bafaed79f40c90c6ad817f3a79#Key-p256-2147483617"},"encrypted_key":"ngqKDJiHBtSxZjvQXsTqqrgC2duPeVMP_c9HIhGJetPzn10kUuwiRfIovoc4zi6o"}],"tag":"KKWrpNfIcFajGMR4Zi9Q-g","iv":"OUKs7uunD39bPEuwOQ"}`)

	plain, err := key.Decrypt(cipher, clientdid)
	if err != nil {
		t.Logf("caused by the JWK is parsed from did doc cannot used to decrypt data: %v", err)
		return
	}
	t.Log(string(plain))
}

func TestEncryptAndDecrypt(t *testing.T) {
	client, err := ioconnect.NewJWKFromDoc([]byte(`{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security#keyAgreementMethod"],"id":"did:io:0xda0f85098a7e88b379f8fcac742c99561137780f","authentication":["did:io:0xda0f85098a7e88b379f8fcac742c99561137780f#Key-p256-2147483616"],"keyAgreement":["did:io:0xaefe2f283b262978a1cabc483410593d62c9c732#Key-p256-2147483617"],"verificationMethod":[{"id":"did:io:0xaefe2f283b262978a1cabc483410593d62c9c732#Key-p256-2147483617","type":"JsonWebKey2020","controller":"did:io:0xda0f85098a7e88b379f8fcac742c99561137780f","publicKeyJwk":{"crv":"P-256","x":"xaKC13yoR2Q6FSF6mrm027-onSs9qud4OApuIE6eFd4","y":"PQk3EoMlKYf9FqorTUN8slXpNSpHyhZdxDBJ9dJmnzE","d":"","kty":"EC","kid":"Key-p256-2147483617"}},{"id":"did:io:0xda0f85098a7e88b379f8fcac742c99561137780f#Key-p256-2147483616","type":"JsonWebKey2020","controller":"did:io:0xda0f85098a7e88b379f8fcac742c99561137780f","publicKeyJwk":{"crv":"P-256","x":"ZxArQGShiyq2Mfdh10V75zsz68Q94YxnW_CeJnJo1Ms","y":"7GLUKpiFI0sOGloNSKXQDwovKMLDGe7hrQqBEaWW66k","d":"","kty":"EC","kid":"Key-p256-2147483616"}}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()

	server, err := ioconnect.NewJWKBySecretBase64("JyBSf1Y9UFIbECdHJRkqZAkfaz16YGwRYyJpXSBwQXJ8RTsZcVMOWStaQxI8bUtafiMtYUE2KkgmI1wBGiQYMw==")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Destroy()

	plain := []byte(`payload`)

	cipher, err := client.Encrypt(plain, server.KeyAgreementKID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	plain, err = server.Decrypt(cipher, client.DID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))

	cipher, err = ioconnect.Encrypt(plain, client.DID(), server.KeyAgreementKID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	plain, err = ioconnect.Decrypt(cipher, client.DID(), server.KeyAgreementKID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}
