package main

import (
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/cmd/didctl/commands"
)

func Command() *cobra.Command {
	root := &cobra.Command{
		Use:   "didctl",
		Short: "didctl is a toolkit for DID operations, help for generating and debugging",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	root.AddCommand(commands.NewInitCmd().Command)
	root.AddCommand(commands.NewVersionCmd().Command)
	root.AddCommand(commands.NewGenerateCmd().Command)
	root.AddCommand(commands.NewVerifiableCredentialCmd().Command)
	root.AddCommand(commands.NewDecryptDataCmd().Command)
	root.AddCommand(commands.NewEncryptDataCmd().Command)

	return root
}

func main() {
	Command().Execute()
}
