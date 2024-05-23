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
	_cmd.Command.Flags().StringVarP(&_cmd.recipient, "recipient", "", "", "recipient's ka jwk base64 secret")
	_ = _cmd.Command.MarkFlagRequired("recipient")
	_cmd.Command.Flags().StringVarP(&_cmd.encryptor, "encryptor", "", "", "encryptor's did, if empty use default config")
	_ = _cmd.Command.MarkFlagRequired("encryptor")

	return _cmd
}

type Decrypt struct {
	Command   *cobra.Command
	cipher    string
	encryptor string
	recipient string
}

/*
func (i *Decrypt) Execute(cmd *cobra.Command) error {
	var key = jwk

	if i.recipient != "" {
		_key, err := ioconnect.NewJWKBySecretBase64(i.recipient)
		if err != nil {
			return errors.Wrap(err, "failed to parse recipient's jwk secret")
		}
		key = _key
	}

	plain, err := ioconnect.Decrypt([]byte(i.cipher), i.encryptor, key.KeyAgreementKID())
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}

	cmd.Println("encryptor did:    ", i.encryptor)
	cmd.Println("recipient ka kid: ", key.KeyAgreementKID())
	cmd.Println("plain data:       ", string(plain))
	return nil
}
*/

func (i *Decrypt) Execute(cmd *cobra.Command) error {
	recipient := jwk.KeyAgreementKID()
	encryptor := jwk.DID()

	if i.recipient != "" {
		s, err := ioconnect.NewJWKBySecretKaOnly(i.recipient)
		if err != nil {
			return errors.Wrap(err, "failed to parse recipient's ka jwk secret")
		}
		recipient = s.KID()
	}
	cmd.Println("recipient ka kid: ", recipient)
	if i.encryptor != "" {
		r, err := ioconnect.NewJWKFromDoc([]byte(i.encryptor))
		if err != nil {
			return errors.Wrap(err, "failed to parse encryptor's doc")
		}
		encryptor = r.DID()
	}
	cmd.Println("encryptor did:    ", encryptor)

	plain, err := ioconnect.Decrypt([]byte(i.cipher), encryptor, recipient)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}
	cmd.Println("plain data:       ", string(plain))
	return nil
}
