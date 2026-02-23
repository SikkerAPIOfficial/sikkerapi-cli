package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type usernameResponse struct {
	Username       string `json:"username"`
	TotalSessions  int64  `json:"totalSessions"`
	ProtocolCounts string `json:"protocolCounts"`
	FirstSeenAt    int64  `json:"firstSeenAt"`
	LastSeenAt     int64  `json:"lastSeenAt"`
}

func newUsernameCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "username <username>",
		Short: "Look up a brute-force username",
		Long: `Check if a username has been observed in brute-force attacks.

Returns session count, protocol breakdown, and first/last seen dates.

Examples:
  sikker username root
  sikker username admin --json
  sikker username ec2-user`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			username := args[0]

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/usernames/lookup/" + url.PathEscape(username))
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status == 404 {
				output.Dim.Printf("\"%s\"", username)
				fmt.Println(" — not found in attack database")
				return nil
			}

			if status != 200 {
				output.Errorf("API error (HTTP %d): %s", status, string(body))
				return fmt.Errorf("API error %d", status)
			}

			var resp usernameResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printUsernameResult(&resp)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printUsernameResult(r *usernameResponse) {
	// Header: "root" — 1,260,789 sessions
	output.Accent.Printf("\"%s\"", r.Username)
	fmt.Printf(" — ")
	output.Bold.Printf("%s", formatCount(r.TotalSessions))
	fmt.Println(" sessions")

	// Time range
	firstSeen := output.FormatEpochAgo(r.FirstSeenAt)
	lastSeen := output.FormatEpochAgo(r.LastSeenAt)
	output.Dim.Print("  First seen: ")
	fmt.Println(firstSeen)
	output.Dim.Print("  Last seen:  ")
	fmt.Println(lastSeen)

	// Protocol breakdown
	protocols := parseProtocolCounts(r.ProtocolCounts)
	if len(protocols) > 0 {
		output.Dim.Print("  Protocols:  ")
		var protoStrs []string
		for _, p := range protocols {
			protoStrs = append(protoStrs, fmt.Sprintf("%s (%s)", strings.ToUpper(p.name), formatCount(p.count)))
		}
		fmt.Println(strings.Join(protoStrs, " · "))
	}
}

type protocolCount struct {
	name  string
	count int64
}

func parseProtocolCounts(jsonStr string) []protocolCount {
	var counts map[string]int64
	if err := json.Unmarshal([]byte(jsonStr), &counts); err != nil {
		return nil
	}

	result := make([]protocolCount, 0, len(counts))
	for name, count := range counts {
		result = append(result, protocolCount{name: name, count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].count > result[j].count
	})
	return result
}

func formatCount(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	var parts []string
	for i := len(s); i > 0; i -= 3 {
		start := i - 3
		if start < 0 {
			start = 0
		}
		parts = append([]string{s[start:i]}, parts...)
	}
	return strings.Join(parts, ",")
}
