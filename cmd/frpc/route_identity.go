package main

import (
	"os"
	"strings"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func routeIDEnvFallback() string {
	return strings.TrimSpace(os.Getenv(envConnectorID))
}

func routeIDWithFallback(cfg *nhpconfig.Config, route nhpconfig.Route, fallbackID string) string {
	if route.ID != "" {
		return route.ID
	}
	if cfg != nil && len(cfg.Routes) == 1 && route.ResourceID == "" {
		return fallbackID
	}
	return ""
}
