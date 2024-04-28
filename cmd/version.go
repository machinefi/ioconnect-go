package cmd

import (
	"fmt"
	"github.com/fatih/color"
)

var (
	Name      string
	Feature   string
	Version   string
	Timestamp string

	BuildVersion string
)

func init() {
	if Name == "" {
		Name = "srv-did-vc"
	}
	if Feature == "" {
		Feature = "unknown"
	}
	if Version == "" {
		Version = "unknown"
	}
	if Timestamp == "" {
		Timestamp = "unknown"
	}

	BuildVersion = fmt.Sprintf("%s@%s_%s", Feature, Version, Timestamp)

	fmt.Printf(color.CyanString("%s: %s\n\n", Name, BuildVersion))
}
