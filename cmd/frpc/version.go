package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/layervai/qurl-connector/pkg/hubpin"
	"github.com/layervai/qurl-connector/pkg/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		if short, _ := cmd.Flags().GetBool("short"); short {
			fmt.Println(version.Short())
			return
		}
		fmt.Println(version.Full())
		fmt.Println(hubTrustPinStatus())
	},
}

func init() {
	versionCmd.Flags().Bool("short", false, "print only the short version string")
}

// hubTrustPinStatus reports whether the developer command has an explicitly
// configured Hub trust pin without attempting a connection.
func hubTrustPinStatus() string {
	if defaultHubServerPublicKeyB64 == "" {
		return "hub trust pin: none (dark build; the all-or-none QURL_CONNECTOR_HUB_* custom deployment triple is required)"
	}
	key, err := hubpin.DecodeServerPublicKeyB64(defaultHubServerPublicKeyB64)
	if err != nil {
		// A provisioned-but-malformed pin also fails closed at `run`
		// (connectorHubBootstrap); version must surface it, never mask it.
		return fmt.Sprintf("hub trust pin: INVALID (%v)", err)
	}
	return fmt.Sprintf("hub trust pin: %s:%d %s (key sha256:%s)",
		defaultHubHost, defaultHubPort, defaultHubServerPublicKeyB64, hubpin.FingerprintSHA256Hex(key))
}
