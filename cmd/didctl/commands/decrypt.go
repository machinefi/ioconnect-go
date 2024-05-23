package commands

import (
	"fmt"
	"os"
	"path/filepath"

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
	_cmd.Command.Flags().Uint32VarP(&_cmd.recipientID, "recipient-id", "", 0, "key id of recipient's secret")
	_ = _cmd.Command.MarkFlagRequired("recipient-id")
	_cmd.Command.Flags().StringVarP(&_cmd.encryptor, "encryptor", "", "", "encryptor's did, if empty use default config")
	_ = _cmd.Command.MarkFlagRequired("encryptor")

	return _cmd
}

type Decrypt struct {
	Command     *cobra.Command
	cipher      string
	encryptor   string
	recipient   string
	recipientID uint32
}

func (i *Decrypt) Execute(cmd *cobra.Command) error {
	recipient := jwk.KeyAgreementKID()
	encryptor := i.encryptor

	defer func() {
		cwd, _ := os.Getwd()
		pattern := filepath.Join(cwd, fmt.Sprintf("%016x.psa_its", i.recipientID))
		os.RemoveAll(pattern)
	}()

	if i.recipient != "" {
		s, err := ioconnect.NewJWKBySecretKaOnly(i.recipient, i.recipientID)
		if err != nil {
			return errors.Wrap(err, "failed to parse recipient's ka jwk secret")
		}
		recipient = s.KID()
	}
	cmd.Println("recipient ka kid: ", recipient)
	cmd.Println("encryptor did:    ", encryptor)

	plain, err := ioconnect.Decrypt([]byte(i.cipher), encryptor, recipient)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}
	cmd.Println("plain data:       ", string(plain))
	return nil
}
