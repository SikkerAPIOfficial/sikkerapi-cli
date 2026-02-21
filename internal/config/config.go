package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultBaseURL = "https://api.sikkerapi.com"
	configDir      = "sikkerapi"
	configFile     = "config.json"
)

// configPath can be overridden in tests.
var configPath string

type Config struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url,omitempty"`
}

func getConfigPath() (string, error) {
	if configPath != "" {
		return configPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".config", configDir, configFile), nil
}

func Load() (*Config, error) {
	cfg := &Config{BaseURL: DefaultBaseURL}

	// Env vars take precedence
	if key := os.Getenv("SIKKERAPI_KEY"); key != "" {
		cfg.APIKey = key
	}
	if url := os.Getenv("SIKKERAPI_URL"); url != "" {
		cfg.BaseURL = url
	}

	path, err := getConfigPath()
	if err != nil {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist — that's fine
		return cfg, nil
	}

	var fileCfg Config
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return cfg, nil
	}

	// File values are defaults; env vars override
	if cfg.APIKey == "" && fileCfg.APIKey != "" {
		cfg.APIKey = fileCfg.APIKey
	}
	if cfg.BaseURL == DefaultBaseURL && fileCfg.BaseURL != "" {
		cfg.BaseURL = fileCfg.BaseURL
	}

	return cfg, nil
}

func Save(cfg *Config) error {
	path, err := getConfigPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("cannot write config: %w", err)
	}

	return nil
}
