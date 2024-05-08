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
	t.Logf("server master secret: %d %d %d %d", secrets[0][0], secrets[0][1], secrets[0][2], secrets[0][3])
	t.Logf("server ka secret:     %d %d %d %d", secrets[1][0], secrets[1][1], secrets[1][2], secrets[1][3])

	serverdoc, _ := json.MarshalIndent(server.Doc(), "", "  ")
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
	t.Logf("client master secret: %d %d %d %d", secrets[0][0], secrets[0][1], secrets[0][2], secrets[0][3])
	t.Logf("client ka secret:     %d %d %d %d", secrets[1][0], secrets[1][1], secrets[1][2], secrets[1][3])

	clientdoc, _ := json.MarshalIndent(client.Doc(), "", "  ")
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

	t.Log("server decrypt by client jwk =======")
	plain, err := server.Decrypt(cipher, client)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))

	t.Log("server decrypt by client did =======")
	plain, err = server.DecryptBySenderDID(cipher, client.DID())
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(plain))
}

/*
func TestDocJWK(t *testing.T) {
	doc := []byte(`{
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security#keyAgreementMethod"
          ],
          "id": "did:io:0xa311d0c815dc5c8911ccf7f3c2708544fc61be72",
          "authentication": [
            "did:io:0xa311d0c815dc5c8911ccf7f3c2708544fc61be72#Key-p256-2147483618"
          ],
          "keyAgreement": [
            "did:io:0x65f1672ea54066ebb60697440be666c4f4e71e90#Key-p256-2147483619"
          ],
          "verificationMethod": [
            {
              "id": "did:io:0x65f1672ea54066ebb60697440be666c4f4e71e90#Key-p256-2147483619",
              "type": "JsonWebKey2020",
              "controller": "did:io:0xa311d0c815dc5c8911ccf7f3c2708544fc61be72",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "FQkXkkXgaStZhF8TlfBNdxaUS67wGsKB5_rczikYtxY",
                "y": "OCx2JQ2BUG-iAnH-h6PFuEsZA0laA_uLvCAk9WwFau8",
                "d": "",
                "kty": "EC",
                "kid": "Key-p256-2147483619"
              }
            },
            {
              "id": "did:io:0xa311d0c815dc5c8911ccf7f3c2708544fc61be72#Key-p256-2147483618",
              "type": "JsonWebKey2020",
              "controller": "did:io:0xa311d0c815dc5c8911ccf7f3c2708544fc61be72",
              "publicKeyJwk": {
                "crv": "P-256",
                "x": "YnAQgGulIncZIayihe2CLtcBS-61wwtK-uRUGLTZceU",
                "y": "AwtYCGJcck4oWTYrfqnrWsbtqGi295HDB4QefyQr0Nc",
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

	cipher, err := client.Encrypt([]byte("something"), server.KeyAgreementKID("io"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(cipher))

	plain, err := server.DecryptBySenderDID(cipher, client.DID("io"))
	if err != nil {
		t.Logf("caused by the JWK is parsed from did doc cannot used to decrypt data: %v", err)
	}
	t.Log(string(plain))
}
*/
