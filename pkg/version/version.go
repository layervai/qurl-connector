package version

import (
	"fmt"
	"runtime"

	frpversion "github.com/fatedier/frp/pkg/util/version"
)

// These variables are set at build time via -ldflags.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func Full() string {
	return fmt.Sprintf("qurl-connector %s %s/%s\nconnector runtime: %s\ngit commit: %s\nbuild date: %s",
		Version, runtime.GOOS, runtime.GOARCH, frpversion.Full(), GitCommit, BuildDate)
}

func Short() string {
	return fmt.Sprintf("qurl-connector %s", Version)
}
