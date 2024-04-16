package commands

import (
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/jwk"
)

func NewVerifiableCredentialSignCmd() *VerifiableCredentialSign {
	_cmd := &VerifiableCredentialSign{}
	_cmd.Command = &cobra.Command{
		Use:   "sign",
		Short: "create a unsigned verifiable credential and sign a verifiable credential token",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	// TODO read issuer from config
	_cmd.Command.Flags().StringVarP(&_cmd.subject, "subject", "", "", "the subject of the verifiable credential")
	_cmd.Command.MarkFlagRequired("subject")
	return _cmd
}

type VerifiableCredentialSign struct {
	Command *cobra.Command
	issuer  string
	subject string
	key     jwk.JWK
}

var vc = `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "id": "http://example.org/credentials/3731",
  "type": [
    "VerifiableCredential"
  ],
  "credentialSubject": [
    {
      "id": "did:io:0xeacdc3f6b30708c401e178b1536150ff60a759de"
    }
  ],
  "issuer": {
    "id": "did:io:0xc16e25aab465d8a6dced725ec0ee7714a8f8ef02"
  },
  "issuanceDate": "2020-08-19T21:41:50Z"
}`

var token = "eyJhbGciOiJFUzI1NiJ9.ewoJImlzcyI6CSJkaWQ6aW86MHhjMTZlMjVhYWI0NjVkOGE2ZGNlZDcyNWVjMGVlNzcxNGE4ZjhlZjAyIiwKCSJ2cCI6CXsKCQkiQGNvbnRleHQiOglbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwgImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sCgkJImlkIjoJImh0dHA6Ly9leGFtcGxlLm9yZy9jcmVkZW50aWFscy8zNzMxIiwKCQkidHlwZSI6CVsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwKCQkiY3JlZGVudGlhbFN1YmplY3QiOglbewoJCQkJImlkIjoJImRpZDppbzoweGVhY2RjM2Y2YjMwNzA4YzQwMWUxNzhiMTUzNjE1MGZmNjBhNzU5ZGUiCgkJCX1dLAoJCSJpc3N1ZXIiOgl7CgkJCSJpZCI6CSJkaWQ6aW86MHhjMTZlMjVhYWI0NjVkOGE2ZGNlZDcyNWVjMGVlNzcxNGE4ZjhlZjAyIgoJCX0sCgkJImlzc3VhbmNlRGF0ZSI6CSIyMDIwLTA4LTE5VDIxOjQxOjUwWiIKCX0KfQ.j3Grm7NBwc_Muak5ndJ6A4Qo3S3zMgy7tG25kLqhwr3IJCZndRZw35ddjBcsCkX-W7j4To1WdJsqhcTlWnMsJQ"

func (i *VerifiableCredentialSign) Execute(cmd *cobra.Command) error {
	// 0. generate a unsigned vc from subject and issuer

	// 1. new a JWTClaim_handle
	// JWTClaim_handle jwt_claim_handle = iotex_jwt_claim_new();

	// 2. generate jwt token
	// iotex_jwt_serialize(jwt_claim_handle, JWT_TYPE_JWS, ES256, mySignJWK);

	cmd.Printf("subject: %s", i.subject)
	cmd.Printf("vc: \n%s", vc)
	cmd.Printf("signed token: %s", token)
	return nil
}

func NewVerifiableCredentialTokenValidateCmd() *VerifiableCredentialTokenValidate {
	_cmd := &VerifiableCredentialTokenValidate{}
	_cmd.Command = &cobra.Command{
		Use:   "verify",
		Short: "verify token and retrieve token subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}
	_cmd.Command.Flags().StringVarP(&_cmd.token, "token", "", "", "subject token")
	_cmd.Command.MarkFlagRequired("token")
	return _cmd
}

type VerifiableCredentialTokenValidate struct {
	Command *cobra.Command
	token   string
}

func (i *VerifiableCredentialTokenValidate) Execute(cmd *cobra.Command) error {
	// 1. verify token and retrieve
	// iotex_jwt_verify(jwt_serialize, JWT_TYPE_JWS, ES256, mySignJWK)
	cmd.Printf("token:     %s\n", i.token)
	cmd.Printf("signed by: %s\n", "did:io:0xc16e25aab465d8a6dced725ec0ee7714a8f8ef02")
	return nil
}

func NewVerifiableCredentialCmd() *VerifiableCredential {
	_cmd := &VerifiableCredential{}
	_cmd.Command = &cobra.Command{
		Use:   "vc",
		Short: "verifiable credential issuring and validating",
	}
	_cmd.Command.AddCommand(NewVerifiableCredentialTokenValidateCmd().Command)
	_cmd.Command.AddCommand(NewVerifiableCredentialSignCmd().Command)
	return _cmd
}

type VerifiableCredential struct {
	Command *cobra.Command
}
