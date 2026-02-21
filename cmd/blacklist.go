package cmd

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type blacklistMeta struct {
	GeneratedAt  int64 `json:"generatedAt"`
	ScoreMinimum int   `json:"scoreMinimum"`
	Limit        int   `json:"limit"`
	Count        int   `json:"count"`
}

type blacklistEntry struct {
	IP              string   `json:"ip"`
	ConfidenceLevel int      `json:"confidenceLevel"`
	LastSeen        int64    `json:"lastSeen"`
	Sessions        int      `json:"sessions"`
	Protocols       []string `json:"protocols"`
	CountryCode     string   `json:"countryCode"`
	ASN             string   `json:"asn"`
	ASNOrg          string   `json:"asnOrg"`
}

type blacklistResponse struct {
	Meta blacklistMeta    `json:"meta"`
	Data []blacklistEntry `json:"data"`
}

func newBlacklistCmd() *cobra.Command {
	var (
		scoreMin        int
		limit           int
		plaintext       bool
		onlyCountries   string
		exceptCountries string
		ipVersion       string
		protocols       string
		minSeverity     string
		onlyASN         string
		exceptASN       string
		ignoreWhitelist bool
		jsonOutput      bool
	)

	cmd := &cobra.Command{
		Use:   "blacklist",
		Short: "Download IP blacklist",
		Long: `Download a scored IP blacklist from SikkerAPI.

Examples:
  sikker blacklist --score-min 75 --limit 1000
  sikker blacklist --plaintext > /etc/blocklist.txt
  sikker blacklist --protocols ssh --only-countries US,CN --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			params := map[string]string{}
			if scoreMin > 0 {
				params["scoreMinimum"] = strconv.Itoa(scoreMin)
			}
			if limit > 0 {
				params["limit"] = strconv.Itoa(limit)
			}
			if plaintext {
				params["plaintext"] = "true"
			}
			if onlyCountries != "" {
				params["onlyCountries"] = onlyCountries
			}
			if exceptCountries != "" {
				params["exceptCountries"] = exceptCountries
			}
			if ipVersion != "" {
				params["ipVersion"] = ipVersion
			}
			if protocols != "" {
				params["protocols"] = protocols
			}
			if minSeverity != "" {
				params["minSeverity"] = minSeverity
			}
			if onlyASN != "" {
				params["onlyAsn"] = onlyASN
			}
			if exceptASN != "" {
				params["exceptAsn"] = exceptASN
			}
			if ignoreWhitelist {
				params["ignoreWhitelist"] = "true"
			}

			c := client.New(cfg)
			body, status, headers, err := c.Get("/v1/key/blacklist" + client.BuildQuery(params))
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status != 200 {
				output.Errorf("API error (HTTP %d): %s", status, string(body))
				return fmt.Errorf("API error %d", status)
			}

			// Plaintext mode — server already returns bare IPs
			if plaintext {
				output.PrintRaw(string(body))
				return nil
			}

			var resp blacklistResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printBlacklistResult(&resp)
			output.PrintRateLimit(headers, "ratelimit")
			return nil
		},
	}

	cmd.Flags().IntVar(&scoreMin, "score-min", 50, "Minimum confidence score (1-100)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of IPs to return")
	cmd.Flags().BoolVar(&plaintext, "plaintext", false, "Output one IP per line (for piping to firewalls)")
	cmd.Flags().StringVar(&onlyCountries, "only-countries", "", "Comma-separated ISO country codes to include")
	cmd.Flags().StringVar(&exceptCountries, "except-countries", "", "Comma-separated ISO country codes to exclude")
	cmd.Flags().StringVar(&ipVersion, "ip-version", "", "IP version: 4, 6, or mixed")
	cmd.Flags().StringVar(&protocols, "protocols", "", "Comma-separated protocol filter")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity: low, medium, high, very_high")
	cmd.Flags().StringVar(&onlyASN, "only-asn", "", "Comma-separated ASNs to include")
	cmd.Flags().StringVar(&exceptASN, "except-asn", "", "Comma-separated ASNs to exclude")
	cmd.Flags().BoolVar(&ignoreWhitelist, "ignore-whitelist", false, "Ignore whitelist filtering")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printBlacklistResult(r *blacklistResponse) {
	output.Dim.Printf("Generated: ")
	fmt.Printf("%s — ", output.FormatEpochAgo(r.Meta.GeneratedAt))
	output.Dim.Printf("Score ≥ ")
	fmt.Printf("%d — ", r.Meta.ScoreMinimum)
	output.Dim.Printf("Count: ")
	fmt.Printf("%d\n\n", r.Meta.Count)

	if len(r.Data) == 0 {
		output.Dim.Println("No IPs matched the given filters.")
		return
	}

	// Table header
	fmt.Printf("  %s  %s  %s  %s  %s\n",
		output.PadRight("IP", 18),
		output.PadRight("SCORE", 7),
		output.PadRight("LAST SEEN", 14),
		output.PadRight("COUNTRY", 9),
		"PROTOCOLS",
	)
	output.Dim.Printf("  %s\n", strings.Repeat("─", 70))

	for _, e := range r.Data {
		// Score color
		scoreStr := strconv.Itoa(e.ConfidenceLevel)
		var coloredScore string
		if e.ConfidenceLevel >= 75 {
			coloredScore = output.Red.Sprint(output.PadRight(scoreStr, 7))
		} else if e.ConfidenceLevel >= 50 {
			coloredScore = output.Yellow.Sprint(output.PadRight(scoreStr, 7))
		} else {
			coloredScore = output.Green.Sprint(output.PadRight(scoreStr, 7))
		}

		lastSeen := output.FormatEpochAgo(e.LastSeen)

		var protoStrs []string
		for _, p := range e.Protocols {
			protoStrs = append(protoStrs, strings.ToUpper(p))
		}

		country := e.CountryCode
		if country == "" {
			country = "—"
		}

		fmt.Printf("  %s  %s  %s  %s  %s\n",
			output.PadRight(e.IP, 18),
			coloredScore,
			output.PadRight(lastSeen, 14),
			output.PadRight(country, 9),
			strings.Join(protoStrs, ", "),
		)
	}
}
