package client

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/sikkerapi/sikker-cli/internal/config"
)

func TestBuildQueryEmpty(t *testing.T) {
	result := BuildQuery(map[string]string{})
	if result != "" {
		t.Errorf("BuildQuery({}) = %q, want empty", result)
	}
}

func TestBuildQuerySkipsEmpty(t *testing.T) {
	result := BuildQuery(map[string]string{
		"a": "1",
		"b": "",
		"c": "3",
	})
	if !strings.HasPrefix(result, "?") {
		t.Fatalf("BuildQuery should start with '?', got %q", result)
	}
	// Map iteration order is random, so parse and sort
	parts := strings.Split(result[1:], "&")
	sort.Strings(parts)
	expected := []string{"a=1", "c=3"}
	sort.Strings(expected)
	if len(parts) != len(expected) {
		t.Fatalf("got %d parts, want %d", len(parts), len(expected))
	}
	for i, p := range parts {
		if p != expected[i] {
			t.Errorf("part[%d] = %q, want %q", i, p, expected[i])
		}
	}
}

func TestBuildQuerySingle(t *testing.T) {
	result := BuildQuery(map[string]string{"key": "value"})
	if result != "?key=value" {
		t.Errorf("BuildQuery = %q, want %q", result, "?key=value")
	}
}

func TestSetHeaders(t *testing.T) {
	SetVersion("1.2.3")
	cfg := &config.Config{
		APIKey:  "sk_test_key",
		BaseURL: "https://api.sikkerapi.com",
	}
	c := New(cfg)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	c.setHeaders(req)

	if got := req.Header.Get("Authorization"); got != "Bearer sk_test_key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer sk_test_key")
	}
	if got := req.Header.Get("User-Agent"); got != "sikker-cli/1.2.3" {
		t.Errorf("User-Agent = %q, want %q", got, "sikker-cli/1.2.3")
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q, want %q", got, "application/json")
	}
}

func TestSetHeadersPreservesAccept(t *testing.T) {
	cfg := &config.Config{
		APIKey:  "sk_test",
		BaseURL: "https://api.sikkerapi.com",
	}
	c := New(cfg)

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Set("Accept", "text/plain")
	c.setHeaders(req)

	if got := req.Header.Get("Accept"); got != "text/plain" {
		t.Errorf("Accept = %q, want %q (should preserve existing)", got, "text/plain")
	}
}
