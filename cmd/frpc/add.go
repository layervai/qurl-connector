package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

var (
	addTarget   string
	addID       string
	addNoVerify bool
)

func init() {
	addCmd.Flags().StringVar(&addTarget, "target", "", "HTTP target URL (e.g. http://localhost:8080)")
	addCmd.Flags().StringVar(&addID, "id", "", "Connector route id / qURL slug (3-64 lowercase letters, digits, and hyphens)")
	addCmd.Flags().BoolVar(&addNoVerify, "no-verify", false, "skip target reachability check")
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new service route",
	Long: `Add a new service route to the qURL Connector configuration.

Examples:
  qurl-connector add --target http://localhost:8080 --id my-app`,
	RunE: runAdd,
}

func runAdd(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(addTarget) == "" {
		return fmt.Errorf("--target is required")
	}
	if strings.TrimSpace(addID) == "" {
		return fmt.Errorf("--id is required")
	}
	if strings.TrimSpace(addID) != addID {
		return fmt.Errorf("invalid route id: %q has leading or trailing whitespace; pass the id exactly as it should be sent as the NHP connector_id", addID)
	}

	// Validate the complete local route before touching the config file. Remote
	// resource work is deliberately absent from add; the next registered run
	// provisions with the device credential.
	routeType, host, port, targetURL, err := nhpconfig.ParseTarget(addTarget)
	if err != nil {
		return err
	}
	if routeType != nhpconfig.RouteTypeHTTP {
		return fmt.Errorf("managed qURL Connector routes require an HTTP target; %q targets are not accepted by the protected Connector server path", routeType)
	}
	if err := nhpconfig.ValidateSlug(addID); err != nil {
		return fmt.Errorf("invalid route id: %w", err)
	}

	ctx := commandContext(cmd)

	// Verify target is reachable unless --no-verify is set
	if !addNoVerify {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			fmt.Printf("Warning: target %s is not reachable: %v\n", addr, err)
		} else {
			conn.Close()
		}
	}

	// Resolve the config path before acquiring its canonical transaction. The
	// complete read/validate/append/save cycle must stay under one lock or two
	// concurrent adds can both read the same snapshot and last-writer-win.
	cfgPath, discoverErr := nhpconfig.Discover(cfgFile)
	if discoverErr != nil {
		// No YAML config found; create a new one in the current
		// directory, or at the explicit --config path when supplied.
		cfgPath = cfgFile
		if cfgPath == "" {
			cfgPath = "qurl-proxy.yaml"
		}
	}
	route := nhpconfig.Route{
		ID:        addID,
		Type:      routeType,
		LocalIP:   host,
		LocalPort: port,
		TargetURL: targetURL,
	}

	_, err = addRouteToConfig(ctx, cfgPath, route, routeIDEnvFallback())
	if err != nil {
		return err
	}

	// Print success.
	fmt.Printf("Added route %q (%s) -> %s:%d\n", route.ID, route.Type, route.LocalIP, route.LocalPort)
	fmt.Printf("Config saved to %s\n", cfgPath)
	fmt.Println("The Connector will provision this route with its device credential on the next run.")
	fmt.Println("Restart `qurl-connector run` to provision and activate it; local admin reload cannot mint a device-owned resource.")
	return nil
}

func addRouteToConfig(ctx context.Context, cfgPath string, route nhpconfig.Route, fallbackID string) (*nhpconfig.Config, error) {
	lockCtx, cancel := context.WithTimeout(ctx, connectorConfigLockWaitTimeout)
	defer cancel()

	var cfg *nhpconfig.Config
	err := nhpconfig.WithFileTransactionContext(lockCtx, cfgPath, func(tx *nhpconfig.FileTransaction) error {
		exists, err := tx.Exists()
		if err != nil {
			return fmt.Errorf("inspect config: %w", err)
		}
		if exists {
			cfg, err = tx.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
		} else {
			// NewDefaulted seeds the same defaults Load would apply
			// (Protocol, PublicDomain, Keepalive, …), keeping a newly
			// created file readable rather than merely valid.
			cfg = nhpconfig.NewDefaulted()
		}

		// A single legacy/headless route can resolve its id from
		// QURL_CONNECTOR_ID at runtime. Honor that fallback before adding a
		// second route so the resulting config is never ambiguous.
		for i, existing := range cfg.Routes {
			existingID := routeIDWithFallback(cfg, existing, fallbackID)
			if existingID == route.ID {
				return fmt.Errorf("a route with id %q already exists", route.ID)
			}
			if existing.ID == "" && existing.ResourceID == "" {
				if existingID != "" {
					return fmt.Errorf("routes[%d] uses %s=%q as its single-route fallback id; set route id: %q in YAML before adding another route", i, envConnectorID, existingID, existingID)
				}
				return fmt.Errorf("routes[%d] has no id; set route id in YAML before adding another route", i)
			}
		}

		// Resource resolution stays deferred until `run`, after native UDP
		// registration has established the registered-agent identity and assigned
		// cell used by the NHP resource exchange.
		cfg.Routes = append(cfg.Routes, route)
		if err := tx.Save(cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
