package commands

import (
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func NewGenerateCmd() *Generate {
	_cmd := &Generate{}
	_cmd.Command = &cobra.Command{
		Use:   "generate",
		Short: "generate a did jwk context and output did and ka information",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}
	_cmd.Command.Flags().StringVarP(&_cmd.secret, "secret", "", "", "jwk secret base64 string for generate jwk context")
	_cmd.Command.Flags().StringVarP(&_cmd.secretPath, "secret-path", "", "", "jwk secret from filesystem for generate jwk context")
	return _cmd
}

type Generate struct {
	Command    *cobra.Command
	secret     string
	secretPath string
}

func (i *Generate) Execute(cmd *cobra.Command) (err error) {
	var (
		key     *ioconnect.JWK
		secrets ioconnect.JWKSecrets
	)

	if i.secret == "" {
		content, err := os.ReadFile(i.secretPath)
		if err == nil {
			i.secret = string(content)
		}
	}

	defer func() {
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		PrintJWK(cmd, key, i.secret == "")
	}()

	if i.secret == "" {
		key, err = ioconnect.NewJWK()
	} else {
		secrets, err = ioconnect.NewJWKSecretsFromBase64(i.secret)
		if err != nil {
			err = errors.Wrap(err, "failed to parse secret")
			return
		}
		key, err = ioconnect.NewJWKBySecret(secrets)
		if err != nil {
			err = errors.Wrap(err, "failed to generate jwk from secret")
			return
		}
	}
	return nil
}
