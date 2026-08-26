package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

var listJSON bool

func init() {
	listCmd.Flags().BoolVar(&listJSON, "json", false, "output in JSON format")
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all service routes",
	Long: `List all service routes in the configuration.

Examples:
  qurl-connector list
  qurl-connector list --json`,
	RunE: runList,
}

func runList(cmd *cobra.Command, _ []string) error {
	cfgPath, discoverErr := nhpconfig.Discover(cfgFile)
	if discoverErr != nil {
		if listJSON {
			return encodeListJSON(nil)
		}
		fmt.Println("No routes configured. Use 'qurl-connector add' to configure a service.")
		return nil
	}

	cfg, err := nhpconfig.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if err := hydrateConnectorResourceIDsReadOnlyContext(commandContext(cmd), cfg); err != nil {
		return fmt.Errorf("loading Connector identity state: %w", err)
	}

	if len(cfg.Routes) == 0 {
		if listJSON {
			return encodeListJSON(nil)
		}
		fmt.Println("No routes configured.")
		return nil
	}
	routes := listRoutes(cfg)

	if listJSON {
		return encodeListJSON(routes)
	}

	// Table output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tTARGET\tPUBLIC URL\tRESOURCE ID")
	publicDomain := cfg.Server.PublicDomain
	if publicDomain == "" {
		publicDomain = "qurl.site"
	}
	for _, r := range routes {
		target := fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort)
		resID := r.ResourceID
		if resID == "" {
			resID = "-"
		}
		publicURL := "-"
		if publicLabel := routePublicLabel(r); publicLabel != "" {
			publicURL = fmt.Sprintf("https://%s.%s", publicLabel, publicDomain)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Type, target, publicURL, resID)
	}
	return w.Flush()
}

// routePublicLabel returns a customer-visible label only for an explicitly
// configured custom FRP route. Managed Connector routes deliberately return
// no label: connector_routing_id is an internal FRP/HRW operand, while the
// private qurl.site lookup host is disclosed only by the qURL control plane after a qURL
// is resolved and the NHP grant is open.
func routePublicLabel(route nhpconfig.Route) string {
	if route.ResourceID != "" {
		return ""
	}
	return route.Subdomain
}

func encodeListJSON(routes []nhpconfig.Route) error {
	if routes == nil {
		routes = []nhpconfig.Route{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(routes)
}

func listRoutes(cfg *nhpconfig.Config) []nhpconfig.Route {
	routes := append([]nhpconfig.Route(nil), cfg.Routes...)
	fallbackID := routeIDEnvFallback()
	for i := range routes {
		// A blank multi-route ID stays blank here so list output mirrors
		// the config shape Validate will reject; the env fallback is only
		// for the single-route headless-startup shape.
		routes[i].ID = routeIDWithFallback(cfg, routes[i], fallbackID)
	}
	return routes
}
