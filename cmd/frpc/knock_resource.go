package main

import (
	"os"
	"strings"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const EnvKnockResourceID = "LAYERV_KNOCK_RESOURCE_ID"

func knockResourceIDOrEmpty(cfg *nhpconfig.Config, resourceID string) string {
	if explicit := strings.TrimSpace(os.Getenv(EnvKnockResourceID)); explicit != "" {
		return explicit
	}
	return cfg.KnockResourceID(resourceID)
}
