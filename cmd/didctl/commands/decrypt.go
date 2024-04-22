package commands

import "github.com/spf13/cobra"

func NewDecryptDataCmd() *Decrypt {
	_cmd := &Decrypt{}

	_cmd.Command = &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt payload with assigned subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.payload, "payload", "", "", "cipher data to decrypt")
	_cmd.Command.MarkFlagRequired("payload")
	_cmd.Command.Flags().StringVarP(&_cmd.token, "token", "", "", "subject did")
	_cmd.Command.MarkFlagRequired("subject")

	return _cmd
}

type Decrypt struct {
	Command *cobra.Command
	token   string
	payload string
}

func (i *Decrypt) Execute(cmd *cobra.Command) error {
	// token => did => serialized doc => doc datatype
	// purpose => VM_PURPOSE_KEY_AGREEMENT
	// iotex_diddoc_verification_method_get(doc, purpose) => index
	// iotex_diddoc_verification_method_get(doc, purpose, index) => JWK
	// iotex_jwe_decrypt(cipherData, Ecdh1puA256kw, A256cbcHs512, subjectSignDID, subjectMasterJWK, myKAKID) => plain data => datatype
	return nil
}
