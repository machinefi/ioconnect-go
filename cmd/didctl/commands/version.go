package commands

import "github.com/spf13/cobra"

func NewVersionCmd() *Version {
	_cmd := &Version{version: "0.0.1"}
	_cmd.Command = &cobra.Command{
		Use:   "version",
		Short: "show version information",
		Run: func(cmd *cobra.Command, args []string) {
			_cmd.Execute(cmd)
		},
	}
	// TODO read version from build info
	return _cmd
}

type Version struct {
	Command *cobra.Command
	version string
}

func (v *Version) Execute(cmd *cobra.Command) {
	cmd.Printf("didctl version: %s\n", v.version)
}
