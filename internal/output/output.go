package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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

// PadRight pads a string to a fixed width.
func PadRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
