package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Point to a non-existent config dir
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("SIKKERAPI_KEY", "")
	t.Setenv("SIKKERAPI_URL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.BaseURL != "https://api.sikkerapi.com" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "https://api.sikkerapi.com")
	}
	if cfg.APIKey != "" {
		t.Errorf("APIKey = %q, want empty", cfg.APIKey)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	t.Setenv("SIKKERAPI_KEY", "sk_envtest123")
	t.Setenv("SIKKERAPI_URL", "https://custom.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.APIKey != "sk_envtest123" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "sk_envtest123")
	}
	if cfg.BaseURL != "https://custom.example.com" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "https://custom.example.com")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "sikkerapi")
	configPath = filepath.Join(configDir, "config.json")

	t.Setenv("SIKKERAPI_KEY", "")
	t.Setenv("SIKKERAPI_URL", "")

	original := &Config{
		APIKey:  "sk_roundtrip_test",
		BaseURL: "https://api.sikkerapi.com",
	}

	if err := Save(original); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.APIKey != original.APIKey {
		t.Errorf("APIKey = %q, want %q", loaded.APIKey, original.APIKey)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "sikkerapi")
	configPath = filepath.Join(configDir, "config.json")

	// Save a file key
	original := &Config{
		APIKey:  "sk_file_key",
		BaseURL: "https://api.sikkerapi.com",
	}
	if err := Save(original); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Env should override
	t.Setenv("SIKKERAPI_KEY", "sk_env_wins")
	t.Setenv("SIKKERAPI_URL", "")

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.APIKey != "sk_env_wins" {
		t.Errorf("APIKey = %q, want %q (env should override file)", loaded.APIKey, "sk_env_wins")
	}
}

func init() {
	// Ensure HOME doesn't interfere
	_ = os.Setenv("HOME", os.TempDir())
}
