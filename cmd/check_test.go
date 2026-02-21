package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sikkerapi/sikker-cli/internal/config"
)

func TestCheckFailAboveTriggered(t *testing.T) {
	resp := checkResponse{
		IP:              "1.2.3.4",
		Found:           true,
		ConfidenceLevel: 85,
		TotalSessions:   10,
	}
	body, _ := json.Marshal(resp)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "999")
		w.Header().Set("X-RateLimit-Limit", "1000")
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer server.Close()

	// Write temp config
	cfg := &config.Config{APIKey: "sk_test123", BaseURL: server.URL}
	configPath := t.TempDir() + "/config.json"
	cfgBytes, _ := json.Marshal(cfg)
	_ = writeTestConfig(configPath, cfgBytes)

	t.Setenv("SIKKERAPI_KEY", "sk_test123")
	t.Setenv("SIKKERAPI_URL", server.URL)

	rootCmd := NewRootCmd("test")
	rootCmd.SetArgs([]string{"check", "1.2.3.4", "--fail-above", "50"})
	err := rootCmd.Execute()

	if err != ErrAboveThreshold {
		t.Errorf("expected ErrAboveThreshold, got %v", err)
	}
}

func TestCheckFailAboveNotTriggered(t *testing.T) {
	resp := checkResponse{
		IP:              "8.8.8.8",
		Found:           false,
		ConfidenceLevel: 0,
	}
	body, _ := json.Marshal(resp)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer server.Close()

	t.Setenv("SIKKERAPI_KEY", "sk_test123")
	t.Setenv("SIKKERAPI_URL", server.URL)

	rootCmd := NewRootCmd("test")
	rootCmd.SetArgs([]string{"check", "8.8.8.8", "--fail-above", "50"})
	err := rootCmd.Execute()

	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCheckNoFailAbove(t *testing.T) {
	resp := checkResponse{
		IP:              "1.2.3.4",
		Found:           true,
		ConfidenceLevel: 95,
		TotalSessions:   50,
	}
	body, _ := json.Marshal(resp)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer server.Close()

	t.Setenv("SIKKERAPI_KEY", "sk_test123")
	t.Setenv("SIKKERAPI_URL", server.URL)

	rootCmd := NewRootCmd("test")
	rootCmd.SetArgs([]string{"check", "1.2.3.4"})
	err := rootCmd.Execute()

	// Without --fail-above, high confidence should NOT cause error
	if err != nil {
		t.Errorf("expected nil error (no --fail-above), got %v", err)
	}
}

func writeTestConfig(path string, data []byte) error {
	return nil // Config loaded from env vars in tests
}
