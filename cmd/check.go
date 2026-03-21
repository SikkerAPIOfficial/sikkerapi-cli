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

type checkResponse struct {
	IP              string          `json:"ip"`
	Found           bool            `json:"found"`
	ConfidenceLevel int             `json:"confidenceLevel"`
	Geolocation     *checkGeo       `json:"geolocation"`
	FirstSeen       *string         `json:"firstSeen"`
	LastSeen        *string         `json:"lastSeen"`
	TotalSessions   int             `json:"totalSessions"`
	TotalEvents     int             `json:"totalEvents"`
	Protocols       []checkProtocol `json:"protocols"`
	Behaviors       []checkBehavior `json:"behaviors"`
	Primitives      []checkPrimitive `json:"primitives"`
}

type checkGeo struct {
	CountryCode string  `json:"countryCode"`
	CountryName string  `json:"countryName"`
	City        *string `json:"city"`
	ASN         *string `json:"asn"`
	ASNOrg      *string `json:"asnOrg"`
	IsTor       bool    `json:"isTor"`
	IsProxy     bool    `json:"isProxy"`
}

type checkProtocol struct {
	Protocol string `json:"protocol"`
	Sessions int    `json:"sessions"`
	Events   int    `json:"events"`
}

type checkBehavior struct {
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	Count       int     `json:"count"`
	Description *string `json:"description"`
}

type checkPrimitive struct {
	Name        string  `json:"name"`
	Count       int     `json:"count"`
	Description *string `json:"description"`
}

// ErrAboveThreshold is returned when --fail-above threshold is exceeded.
var ErrAboveThreshold = fmt.Errorf("confidence above threshold")

func newCheckCmd() *cobra.Command {
	var (
		maxAge          int
		verbose         bool
		protocols       string
		exclude         string
		ignoreWhitelist bool
		jsonOutput      bool
		failAbove       int
	)

	cmd := &cobra.Command{
		Use:   "check <ip>",
		Short: "Look up IP reputation",
		Long: `Check an IP address against the SikkerAPI threat intelligence database.

Examples:
  sikker check 8.8.8.8
  sikker check 1.2.3.4 --max-age 30 --protocols ssh,http
  sikker check 1.2.3.4 --json
  sikker check 1.2.3.4 --fail-above 50 || block_ip 1.2.3.4`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			ip := args[0]
			params := map[string]string{}
			if maxAge > 0 {
				params["maxAge"] = strconv.Itoa(maxAge)
			}
			if !verbose {
				params["verbose"] = "false"
			}
			if protocols != "" {
				params["protocols"] = protocols
			}
			if exclude != "" {
				params["exclude"] = exclude
			}
			if ignoreWhitelist {
				params["ignoreWhitelist"] = "true"
			}

			c := client.New(cfg)
			body, status, headers, err := c.Get("/v1/key/check/" + ip + client.BuildQuery(params))
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

			var resp checkResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printCheckResult(&resp)
			output.PrintRateLimit(headers, "ratelimit")

			if failAbove > 0 && resp.ConfidenceLevel >= failAbove {
				return ErrAboveThreshold
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&maxAge, "max-age", 0, "Maximum data age in seconds")
	cmd.Flags().BoolVar(&verbose, "verbose", true, "Include detailed data")
	cmd.Flags().StringVar(&protocols, "protocols", "", "Comma-separated protocol filter")
	cmd.Flags().StringVar(&exclude, "exclude", "", "Fields to exclude from response")
	cmd.Flags().BoolVar(&ignoreWhitelist, "ignore-whitelist", false, "Ignore whitelist filtering")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	cmd.Flags().IntVar(&failAbove, "fail-above", 0, "Exit with code 1 if confidence >= this value")

	return cmd
}

func printCheckResult(r *checkResponse) {
	// Header line
	if !r.Found {
		fmt.Printf("%s — Confidence: %d — ", r.IP, r.ConfidenceLevel)
		output.Dim.Println("Not found")
		return
	}

	lastSeen := "—"
	if r.LastSeen != nil {
		lastSeen = output.FormatTimeAgo(*r.LastSeen)
	}

	output.Accent.Printf("%s", r.IP)
	fmt.Printf(" — Confidence: ")
	if r.ConfidenceLevel >= 75 {
		output.Red.Printf("%d", r.ConfidenceLevel)
	} else if r.ConfidenceLevel >= 50 {
		output.Yellow.Printf("%d", r.ConfidenceLevel)
	} else {
		output.Green.Printf("%d", r.ConfidenceLevel)
	}
	fmt.Printf(" — Last seen: %s\n", lastSeen)

	// Geolocation
	if r.Geolocation != nil {
		geo := r.Geolocation
		var parts []string
		if geo.CountryCode != "" {
			parts = append(parts, geo.CountryCode)
		}
		if geo.City != nil && *geo.City != "" {
			parts = append(parts, *geo.City)
		}
		if geo.ASN != nil && *geo.ASN != "" {
			asnStr := "AS" + *geo.ASN
			if geo.ASNOrg != nil && *geo.ASNOrg != "" {
				asnStr += " (" + *geo.ASNOrg + ")"
			}
			parts = append(parts, asnStr)
		}
		if len(parts) > 0 {
			output.Dim.Print("  Location:  ")
			fmt.Println(strings.Join(parts, " — "))
		}
		if geo.IsTor || geo.IsProxy {
			output.Dim.Print("  Flags:     ")
			var flags []string
			if geo.IsTor {
				flags = append(flags, output.Yellow.Sprint("TOR"))
			}
			if geo.IsProxy {
				flags = append(flags, output.Yellow.Sprint("PROXY"))
			}
			fmt.Println(strings.Join(flags, " · "))
		}
	}

	// Sessions
	output.Dim.Print("  Sessions:  ")
	fmt.Printf("%d across %d protocol(s)\n", r.TotalSessions, len(r.Protocols))

	// Protocols
	if len(r.Protocols) > 0 {
		output.Dim.Print("  Protocols: ")
		var protoStrs []string
		for _, p := range r.Protocols {
			protoStrs = append(protoStrs, fmt.Sprintf("%s (%d)", strings.ToUpper(p.Protocol), p.Sessions))
		}
		fmt.Println(strings.Join(protoStrs, " · "))
	}

	// Behaviors
	if len(r.Behaviors) > 0 {
		// Find max name length for alignment
		maxBehaviorLen := 0
		for _, b := range r.Behaviors {
			if len(b.Name) > maxBehaviorLen {
				maxBehaviorLen = len(b.Name)
			}
		}
		pad := maxBehaviorLen + 2

		output.Dim.Println("  Behaviors:")
		for _, b := range r.Behaviors {
			fmt.Print("    ")
			fmt.Printf("%-*s", pad, b.Name)
			switch b.Severity {
			case "very_high":
				output.Red.Printf("%-10s", b.Severity)
			case "high":
				output.Yellow.Printf("%-10s", b.Severity)
			case "medium":
				output.Yellow.Printf("%-10s", b.Severity)
			default:
				output.Dim.Printf("%-10s", b.Severity)
			}
			output.Dim.Printf(" ×%d\n", b.Count)
		}
	}

	// Primitives
	if len(r.Primitives) > 0 {
		maxPrimLen := 0
		for _, p := range r.Primitives {
			if len(p.Name) > maxPrimLen {
				maxPrimLen = len(p.Name)
			}
		}
		pad := maxPrimLen + 2

		output.Dim.Println("  Primitives:")
		for _, p := range r.Primitives {
			fmt.Print("    ")
			fmt.Printf("%-*s", pad, p.Name)
			output.Dim.Printf("×%d\n", p.Count)
		}
	}
}
