package commands

import (
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
	_cmd.Command.Flags().StringVarP(&_cmd.encryptor, "encryptor", "", "", "(optional) encryptor's did, if empty use the default jwk")

	return _cmd
}

type Encrypt struct {
	Command   *cobra.Command
	plain     string
	recipient string
	encryptor string
}

func (i *Encrypt) SetPayload(plain string) {
	i.plain = plain
}

func (i *Encrypt) SetRecipient(recipient string) {
	i.recipient = recipient
}

func (i *Encrypt) Execute(cmd *cobra.Command) error {
	var encryptor = jwk.DID()

	if i.encryptor != "" {
		encryptor = i.encryptor
	}

	recipient, err := ioconnect.NewJWKFromDoc([]byte(i.recipient))
	if err != nil {
		return errors.Wrap(err, "failed to generate jwk from recipient doc")
	}

	cipher, err := ioconnect.Encrypt([]byte(i.plain), encryptor, recipient.KeyAgreementKID())
	if err != nil {
		return errors.Wrapf(err, "failed to encrypt, encryptor: %s recipient: %s", encryptor, recipient.KeyAgreementDID())
	}

	cmd.Println("encryptor did:    ", encryptor)
	cmd.Println("recipient ka kid: ", recipient.KeyAgreementKID())
	cmd.Println("cipher data:      ", string(cipher))
	return nil
}
