package commands

import (
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/pkg/ioconnect"
)

func NewTokenCmd() *Token {
	_cmd := &Token{}
	_cmd.Command = &cobra.Command{
		Use:   "token",
		Short: "sign or verify token",
	}

	_cmd.Command.AddCommand(NewVerifyTokenCmd().Command)
	_cmd.Command.AddCommand(NewSignTokenCmd().Command)

	return _cmd
}

type Token struct {
	Command *cobra.Command
}

func NewVerifyTokenCmd() *VerifyToken {
	_cmd := &VerifyToken{}
	_cmd.Command = &cobra.Command{
		Use:   "verify",
		Short: "verify token and retrieve token subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.token, "token", "", "", "token value")
	_ = _cmd.Command.MarkFlagRequired("token")

	return _cmd
}

type VerifyToken struct {
	Command *cobra.Command
	token   string
}

func (i *VerifyToken) Execute(cmd *cobra.Command) error {
	subject, err := jwk.VerifyToken(i.token)
	if err != nil {
		return err
	}
	cmd.Println("subject: ", subject)
	return nil
}

func NewSignTokenCmd() *SignToken {
	_cmd := &SignToken{}
	_cmd.Command = &cobra.Command{
		Use:   "sign",
		Short: "sign token by subject",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}

	_cmd.Command.Flags().StringVarP(&_cmd.subject, "subject", "", "", "subject did")
	_ = _cmd.Command.MarkFlagRequired("subject")

	return _cmd
}

type SignToken struct {
	Command *cobra.Command
	subject string
}

func (i *SignToken) Execute(cmd *cobra.Command) error {
	vc := ioconnect.NewVerifiableCredentialByIssuerAndSubjectDIDs(jwk.DID(), i.subject)
	token, err := jwk.SignTokenByVC(vc)
	if err != nil {
		return err
	}
	cmd.Println(token)
	return nil
}
