package version

import (
	_ "embed"
	"strings"
)

// VERSION is the product version source for plain Go builds, Make and Docker.
// Commit and BuildDate identify a build independently of its product version.
//
//go:embed VERSION
var sourceVersion string

var (
	Version   = strings.TrimSpace(sourceVersion)
	Commit    = "dev"
	BuildDate = ""
)
