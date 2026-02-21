package output

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestFormatTimeAgoEmpty(t *testing.T) {
	if got := FormatTimeAgo(""); got != "—" {
		t.Errorf("FormatTimeAgo(\"\") = %q, want \"—\"", got)
	}
}

func TestFormatTimeAgoInvalid(t *testing.T) {
	if got := FormatTimeAgo("not-a-date"); got != "not-a-date" {
		t.Errorf("FormatTimeAgo(invalid) = %q, want passthrough", got)
	}
}

func TestFormatTimeAgoJustNow(t *testing.T) {
	ts := time.Now().UTC().Format(time.RFC3339)
	if got := FormatTimeAgo(ts); got != "just now" {
		t.Errorf("FormatTimeAgo(now) = %q, want \"just now\"", got)
	}
}

func TestFormatTimeAgoMinutes(t *testing.T) {
	ts := time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	got := FormatTimeAgo(ts)
	if got != "15m ago" {
		t.Errorf("FormatTimeAgo(-15m) = %q, want \"15m ago\"", got)
	}
}

func TestFormatTimeAgoHours(t *testing.T) {
	ts := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	got := FormatTimeAgo(ts)
	if got != "3h ago" {
		t.Errorf("FormatTimeAgo(-3h) = %q, want \"3h ago\"", got)
	}
}

func TestFormatTimeAgoDays(t *testing.T) {
	ts := time.Now().Add(-5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	got := FormatTimeAgo(ts)
	if got != "5d ago" {
		t.Errorf("FormatTimeAgo(-5d) = %q, want \"5d ago\"", got)
	}
}

func TestFormatTimeAgoOld(t *testing.T) {
	ts := "2020-01-15T12:00:00Z"
	got := FormatTimeAgo(ts)
	if got != "Jan 15, 2020" {
		t.Errorf("FormatTimeAgo(old) = %q, want \"Jan 15, 2020\"", got)
	}
}

func TestFormatEpochAgoZero(t *testing.T) {
	if got := FormatEpochAgo(0); got != "—" {
		t.Errorf("FormatEpochAgo(0) = %q, want \"—\"", got)
	}
}

func TestFormatEpochAgoRecent(t *testing.T) {
	ms := time.Now().UnixMilli()
	if got := FormatEpochAgo(ms); got != "just now" {
		t.Errorf("FormatEpochAgo(now) = %q, want \"just now\"", got)
	}
}

func TestPadRight(t *testing.T) {
	tests := []struct {
		input    string
		width    int
		expected string
	}{
		{"hi", 5, "hi   "},
		{"hello", 5, "hello"},
		{"toolong", 4, "tool"},
		{"", 3, "   "},
	}
	for _, tt := range tests {
		got := PadRight(tt.input, tt.width)
		if got != tt.expected {
			t.Errorf("PadRight(%q, %d) = %q, want %q", tt.input, tt.width, got, tt.expected)
		}
	}
}

func TestPrintRateLimitNoHeaders(t *testing.T) {
	// Should not panic with empty headers
	headers := http.Header{}
	PrintRateLimit(headers, "ratelimit")
	PrintRateLimit(headers, "report")
	PrintRateLimit(headers, "taxii")
}

func TestPrintRateLimitRatelimit(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-RateLimit-Remaining", "950")
	headers.Set("X-RateLimit-Limit", "1000")
	resetTime := time.Now().Add(2 * time.Hour).Unix()
	headers.Set("X-RateLimit-Reset", strconv.FormatInt(resetTime, 10))

	// Just verify it doesn't panic — output goes to stdout
	PrintRateLimit(headers, "ratelimit")
}

func TestPrintRateLimitReport(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Report-Remaining", "45")
	headers.Set("X-Report-Limit", "50")
	PrintRateLimit(headers, "report")
}

func TestPrintRateLimitTaxii(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-TAXII-Remaining", "9500")
	headers.Set("X-TAXII-Limit", "10000")
	PrintRateLimit(headers, "taxii")
}

func TestPrintRateLimitMissingOne(t *testing.T) {
	// Only remaining, no limit — should silently skip
	headers := http.Header{}
	headers.Set("X-RateLimit-Remaining", "950")
	PrintRateLimit(headers, "ratelimit")
}

func TestPrintRateLimitResetMinutes(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-RateLimit-Remaining", "100")
	headers.Set("X-RateLimit-Limit", "1000")
	resetTime := time.Now().Add(30 * time.Minute).Unix()
	headers.Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))
	PrintRateLimit(headers, "ratelimit")
}
