package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const (
	desktopConfigMaxBytes    = 1024 * 1024
	desktopConfigReadTimeout = 5 * time.Second
)

type desktopConfigReadResult struct {
	data []byte
	err  error
}

var desktopConfigCmd = &cobra.Command{
	Use:    "desktop-config",
	Short:  "Internal qURL Desktop configuration transaction",
	Hidden: true,
}

var desktopConfigReplaceCmd = &cobra.Command{
	Use:    "replace",
	Short:  "Validate and replace a Desktop-managed configuration from stdin",
	Hidden: true,
	RunE:   runDesktopConfigReplace,
}

func init() {
	desktopConfigCmd.AddCommand(desktopConfigReplaceCmd)
}

func runDesktopConfigReplace(cmd *cobra.Command, _ []string) error {
	if strings.TrimSpace(cfgFile) == "" {
		return fmt.Errorf("--config is required")
	}
	return replaceDesktopConfig(commandContext(cmd), cfgFile, os.Stdin)
}

func replaceDesktopConfig(ctx context.Context, configPath string, input io.Reader) error {
	readCtx, cancel := context.WithTimeout(ctx, desktopConfigReadTimeout)
	defer cancel()
	result := make(chan desktopConfigReadResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(input, desktopConfigMaxBytes+1))
		result <- desktopConfigReadResult{data: data, err: err}
	}()

	var data []byte
	var err error
	select {
	case read := <-result:
		data, err = read.data, read.err
	case <-readCtx.Done():
		if closer, ok := input.(io.Closer); ok {
			_ = closer.Close()
		}
		return fmt.Errorf("read Desktop config from stdin: %w", readCtx.Err())
	}
	if err != nil {
		return fmt.Errorf("read Desktop config from stdin: %w", err)
	}
	if len(data) > desktopConfigMaxBytes {
		return fmt.Errorf("Desktop config exceeds %d-byte limit", desktopConfigMaxBytes)
	}
	lockCtx, cancelLock := context.WithTimeout(ctx, connectorConfigLockWaitTimeout)
	defer cancelLock()
	return nhpconfig.WithFileTransactionContext(lockCtx, configPath, func(tx *nhpconfig.FileTransaction) error {
		if err := tx.ReplaceYAML(data, "stdin"); err != nil {
			return fmt.Errorf("replace Desktop config: %w", err)
		}
		return nil
	})
}
