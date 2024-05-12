package commands

import (
	"bytes"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func NewEncryptDataCmd() *Encrypt {
	_cmd := &Encrypt{}

	_cmd.Command = &cobra.Command{
		Use:   "encrypt",
		Short: "encrypt plain data with recipient did document",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.plain, "plain", "", "", "* plain data to encrypt")
	_ = _cmd.Command.MarkFlagRequired("plain")
	_cmd.Command.Flags().StringVarP(&_cmd.recipient, "recipient", "", "", "* recipient did document")
	_ = _cmd.Command.MarkFlagRequired("recipient")
	_cmd.Command.Flags().StringVarP(&_cmd.secrets, "secret", "", "", "(optional) encryptor's secret, if empty use the default jwk context")

	return _cmd
}

type Encrypt struct {
	Command   *cobra.Command
	plain     string
	recipient string
	secrets   string
}

func (i *Encrypt) SetPayload(plain string) {
	i.plain = plain
}

func (i *Encrypt) SetRecipient(recipient string) {
	i.recipient = recipient
}

func (i *Encrypt) Exec() (cipher []byte, err error) {
	var encryptor = jwk

	if i.secrets != "" {
		encryptor, err = ioconnect.NewJWKBySecretBase64(i.secrets)
		if err != nil {
			return nil, err
		}
	}

	recipient, err := ioconnect.NewJWKFromDoc([]byte(i.recipient))
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate jwk from recipient doc")
	}

	cipher, err = encryptor.Encrypt([]byte(i.plain), recipient.KeyAgreementKID())
	if err != nil {
		err = errors.Wrapf(err, "failed to encrypt, encryptor: %s recipient: %s", encryptor.DID(), recipient.DID())
	}

	return
}

func (i *Encrypt) Execute(cmd *cobra.Command) error {
	cipher, err := i.Exec()
	if err != nil {
		return err
	}

	cipher = bytes.Replace(cipher, []byte("\t"), nil, -1)
	cipher = bytes.Replace(cipher, []byte(" "), nil, -1)
	cipher = bytes.Replace(cipher, []byte("\n"), nil, -1)
	cmd.Println(string(cipher))
	return nil
}
