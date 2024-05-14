package commands

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func NewDecryptDataCmd() *Decrypt {
	_cmd := &Decrypt{}

	_cmd.Command = &cobra.Command{
		Use:   "decrypt",
		Short: "decrypt payload with assigned subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.cipher, "cipher", "", "", "cipher data to decrypt")
	_ = _cmd.Command.MarkFlagRequired("cipher")
	_cmd.Command.Flags().StringVarP(&_cmd.recipient, "recipient", "", "", "recipient did")
	_cmd.Command.Flags().StringVarP(&_cmd.secrets, "secret", "", "", "decryptor's secret, if empty use default config")

	return _cmd
}

type Decrypt struct {
	Command   *cobra.Command
	cipher    string
	secrets   string
	recipient string
}

func (i *Decrypt) Exec() (plain []byte, err error) {
	var decryptor = jwk

	if i.secrets != "" {
		decryptor, err = ioconnect.NewJWKBySecretBase64(i.secrets)
		if err != nil {
			return nil, err
		}
	}

	plain, err = decryptor.Decrypt([]byte(i.cipher), i.recipient)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decrypt")
	}

	return
}

func (i *Decrypt) Execute(cmd *cobra.Command) error {
	plain, err := i.Exec()
	if err != nil {
		return err
	}

	cmd.Println(string(plain))

	return nil
}
