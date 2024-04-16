package commands

import "github.com/spf13/cobra"

func NewInitCmd() *Init {
	_cmd := &Init{}

	_cmd.Command = &cobra.Command{
		Use:   "init",
		Short: "generate the master key init didctl command config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return _cmd.Execute(cmd)
		},
	}
	return _cmd
}

type Init struct {
	Command *cobra.Command
}

func (Init) Execute(cmd *cobra.Command) error {
	// 1. read config from $HOME/.config/didctl/config.json
	// 2. init a master key
	// 3. write master key to config file
	cmd.Println("didctl initialized, the config is put to $HOME/.config/didctl/config.json")
	return nil
}
