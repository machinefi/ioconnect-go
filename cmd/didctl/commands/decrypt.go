package commands

import "github.com/spf13/cobra"

func NewDecryptDataCmd() *Encrypt {
	_cmd := &Encrypt{}

	_cmd.Command = &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt payload with assigned subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.payload, "payload", "", "", "cipher data to decrypt")
	_cmd.Command.MarkFlagRequired("payload")
	_cmd.Command.Flags().StringVarP(&_cmd.subject, "subject", "", "", "subject did")
	_cmd.Command.MarkFlagRequired("subject")

	return _cmd
}

type Decrypt struct {
	Command *cobra.Command
	payload string
	subject string
}

func (i *Decrypt) Execute(cmd *cobra.Command) error {
	// iotex_jwe_decrypt(jwe_json, Ecdh1puA256kw, A256cbcHs512, peerSignDID, peerSignJWK, myKAKID);
	return nil
}
