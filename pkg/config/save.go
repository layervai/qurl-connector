package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Save marshals cfg and atomically writes it through a pinned, locked config
// namespace. Parent directories are durably created if they do not exist.
func Save(cfg *Config, path string) error {
	data, err := marshalConfig(cfg)
	if err != nil {
		return err
	}
	return WithFileTransaction(path, func(tx *FileTransaction) error {
		return tx.saveMarshaled(data)
	})
}

func marshalConfig(cfg *Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}
	return data, nil
}
