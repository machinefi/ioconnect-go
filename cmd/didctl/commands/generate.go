package commands

import "github.com/spf13/cobra"

func NewDIDGenerateCmd() *DID {
	_cmd := &DID{}
	_cmd.Command = &cobra.Command{
		Use:   "did",
		Short: "generate a did identifier",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}
	_cmd.Command.Flags().StringVarP(&_cmd.method, "method", "", "", "did method")
	return _cmd
}

type DID struct {
	Command *cobra.Command
	method  string
}

func (i *DID) Execute(cmd *cobra.Command) error {
	switch i.method {
	case "io":
	case "key":
	default:
		i.method = "io"
	}
	// 1. new a jwk
	// iotex_jwk_generate(
	//  JWK type ==> support EC(elliptic curve only until now), JWKTYPE_EC
	//	Key algorithm ==> JWK_SUPPORT_KEY_ALG_P256,
	// 	Lifetime ==> IOTEX_JWK_LIFETIME_VOLATILE,
	// 	Key Usage ==> PSA_KEY_USAGE_SIGN_HASH|PSA_KEY_USAGE_VERIFY_HASH|PSA_KEY_USAGE_EXPORT,
	// 	Algorithm ==> PSA_ALG_ECDSA(PSA_ALG_SHA_256),
	// 	KeyID ==> &mySignKeyID,
	// ) => *JWK

	// 2. generate did with jwk
	// iotex_did_generate(method, *JWK) ==> string

	cmd.Println("generated did: did:io:0xb48ec7e65b6463d7f8c7e6e659dd375c88abdb9b")
	return nil
}

func NewDIDDocGenerateCmd() *DIDDoc {
	_cmd := &DIDDoc{}
	_cmd.Command = &cobra.Command{
		Use:   "doc",
		Short: "generate a did document",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}
	_cmd.Command.Flags().StringVarP(&_cmd.method, "method", "", "", "did method")
	_cmd.Command.Flags().StringVarP(&_cmd.subject, "subject", "", "", "did document subject(owner)")
	_cmd.Command.MarkFlagRequired("subject")
	return _cmd
}

type DIDDoc struct {
	Command *cobra.Command
	method  string
	subject string
}

func (i *DIDDoc) Execute(cmd *cobra.Command) error {
	// 1. generate a key agreement JWK
	// iotex_jwk_generate(
	//	JWKTYPE_EC,
	//	JWK_SUPPORT_KEY_ALG_P256,
	// 	IOTEX_JWK_LIFETIME_VOLATILE,
	// 	PSA_KEY_USAGE_DERIVE,
	// 	PSA_ALG_ECDH,
	// 	&myKeyAgreementKeyID); => *JWK

	// 2. generate key agreement did
	// iotex_did_generate("io", JWK); did:io:...

	// 3. generate key agreement did key(with #key fragment)
	// iotex_jwk_generate_kid("io", peerKAJWK); did:io:...#key....

	// 4. compose a did doc

	cmd.Println("generated did: did:io:0xb48ec7e65b6463d7f8c7e6e659dd375c88abdb9b")
	return nil
}

func NewGenerateCmd() *Generate {
	_cmd := &Generate{}

	_cmd.Command = &cobra.Command{
		Use:   "generate",
		Short: "generate did or did document",
	}
	_cmd.Command.AddCommand(NewDIDDocGenerateCmd().Command)
	_cmd.Command.AddCommand(NewDIDGenerateCmd().Command)

	return _cmd
}

type Generate struct {
	Command *cobra.Command
}
