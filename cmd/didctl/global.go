package main

import (
	"github.com/spf13/cobra"

	"github.com/machinefi/ioconnect-go/cmd/didctl/commands"
)

func NewGlobal() *Global {
	_cmd := &Global{}
	_cmd.Command = &cobra.Command{
		Use:   "info",
		Short: "show global information",
		Run: func(cmd *cobra.Command, args []string) {
			_cmd.Execute(cmd)
		},
	}

	return _cmd
}

type Global struct {
	Command *cobra.Command
}

func (v *Global) Execute(cmd *cobra.Command) {
	commands.PrintJWK(cmd, commands.GlobalKey(), true)
}

func NewVersion() *VersionCmd {
	_cmd := &VersionCmd{}
	_cmd.Command = &cobra.Command{
		Use:   "version",
		Short: "show didctl version info",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("didctl: ", BuildVersion)
		},
	}
	return _cmd
}

type VersionCmd struct {
	Command *cobra.Command
}
