package main

import (
	"fmt"
)

var (
	Name      string
	Feature   string
	Version   string
	CommitID  string
	Timestamp string

	BuildVersion string
)

func init() {
	if Name == "" {
		Name = "didctl"
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

	BuildVersion = fmt.Sprintf("%s@%s-%s_%s", Feature, Version, CommitID, Timestamp)
}
