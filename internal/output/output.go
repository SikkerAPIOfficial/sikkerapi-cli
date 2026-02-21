package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	Accent = color.New(color.FgCyan)
	Dim    = color.New(color.FgHiBlack)
	Green  = color.New(color.FgGreen)
	Yellow = color.New(color.FgYellow)
	Red    = color.New(color.FgRed)
	Bold   = color.New(color.Bold)
	White  = color.New(color.FgWhite)
)

// PrintJSON prints raw JSON to stdout, pretty-printed.
func PrintJSON(data []byte) {
	var out bytes.Buffer
	if json.Indent(&out, data, "", "  ") == nil {
		fmt.Println(out.String())
	} else {
		fmt.Println(string(data))
	}
}

// PrintRaw prints raw text to stdout with no formatting.
func PrintRaw(data string) {
	fmt.Print(data)
}

// Error prints an error message to stderr.
func Error(msg string) {
	Red.Fprintln(os.Stderr, msg)
}

// Errorf prints a formatted error message to stderr.
func Errorf(format string, args ...interface{}) {
	Red.Fprintf(os.Stderr, format+"\n", args...)
}

// Success prints a success message.
func Success(msg string) {
	Green.Println(msg)
}

// FormatTimeAgo formats an ISO timestamp or epoch into a relative time string.
func FormatTimeAgo(timestamp string) string {
	if timestamp == "" {
		return "—"
	}

	var t time.Time
	var err error

	t, err = time.Parse(time.RFC3339, timestamp)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, timestamp)
	}
	if err != nil {
		return timestamp
	}

	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	case diff < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
	default:
		return t.Format("Jan 02, 2006")
	}
}

// FormatEpochAgo formats an epoch millisecond timestamp into a relative time string.
func FormatEpochAgo(epochMs int64) string {
	if epochMs == 0 {
		return "—"
	}
	t := time.UnixMilli(epochMs)
	diff := time.Since(t)
	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	case diff < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	case diff < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
	default:
		return t.Format("Jan 02, 2006")
	}
}

// PrintRateLimit prints a dim quota line based on response headers.
// kind: "ratelimit" (check/blacklist), "report" (report/bulk-report), "taxii" (taxii)
func PrintRateLimit(headers http.Header, kind string) {
	var remaining, limit string

	switch kind {
	case "ratelimit":
		remaining = headers.Get("X-RateLimit-Remaining")
		limit = headers.Get("X-RateLimit-Limit")
	case "report":
		remaining = headers.Get("X-Report-Remaining")
		limit = headers.Get("X-Report-Limit")
	case "taxii":
		remaining = headers.Get("X-TAXII-Remaining")
		limit = headers.Get("X-TAXII-Limit")
	}

	if remaining == "" || limit == "" {
		return
	}

	line := fmt.Sprintf("  Quota: %s / %s remaining", remaining, limit)

	if kind == "ratelimit" {
		if resetStr := headers.Get("X-RateLimit-Reset"); resetStr != "" {
			if resetUnix, err := strconv.ParseInt(resetStr, 10, 64); err == nil {
				resetTime := time.Unix(resetUnix, 0)
				diff := time.Until(resetTime)
				if diff > 0 {
					if diff < time.Hour {
						line += fmt.Sprintf(" (resets in %dm)", int(diff.Minutes()))
					} else {
						line += fmt.Sprintf(" (resets in %dh)", int(diff.Hours()))
					}
				}
			}
		}
	}

	Dim.Println(line)
}

// PadRight pads a string to a fixed width.
func PadRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
