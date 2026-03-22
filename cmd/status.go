package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type statusResponse struct {
	Tier   statusTier   `json:"tier"`
	Quotas statusQuotas `json:"quotas"`
	Alerts statusAlerts `json:"alerts"`
}

type statusTier struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type statusQuotas struct {
	Lookups   quotaInfo `json:"lookups"`
	Reports   quotaInfo `json:"reports"`
	Blacklist quotaInfo `json:"blacklist"`
	Taxii     quotaInfo `json:"taxii"`
}

type quotaInfo struct {
	Used      int `json:"used"`
	Limit     int `json:"limit"`
	Remaining int `json:"remaining"`
}

type statusAlerts struct {
	IpAlerts       alertInfo `json:"ipAlerts"`
	RangeAlerts    alertInfo `json:"rangeAlerts"`
	UsernameAlerts alertInfo `json:"usernameAlerts"`
	EmailAlerts    alertInfo `json:"emailAlerts"`
}

type alertInfo struct {
	Current int `json:"current"`
	Limit   int `json:"limit"`
}

func newStatusCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show API key status, quota usage, and alerts",
		Long: `Display your API key's current tier, daily quota usage, and alert counts.

Examples:
  sikker status
  sikker status --json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/key/status")
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status != 200 {
				printAPIError(body, status)
				return fmt.Errorf("API error %d", status)
			}

			var resp statusResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printStatus(&resp, cfg.APIKey)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printStatus(s *statusResponse, apiKey string) {
	// Key + tier
	masked := apiKey
	if len(masked) > 10 {
		masked = masked[:6] + "..." + masked[len(masked)-4:]
	}

	fmt.Println()
	output.Dim.Print("  Key         ")
	fmt.Println(masked)
	output.Dim.Print("  Tier        ")
	output.Accent.Println(s.Tier.Name)
	fmt.Println()

	// Quotas
	output.Dim.Println("  Daily Quotas")
	printQuotaLine("Lookups", s.Quotas.Lookups)
	printQuotaLine("Reports", s.Quotas.Reports)
	printQuotaLine("Blacklist", s.Quotas.Blacklist)
	printQuotaLine("TAXII", s.Quotas.Taxii)
	fmt.Println()

	// Alerts
	output.Dim.Println("  Alerts")
	printAlertLine("IP", s.Alerts.IpAlerts)
	printAlertLine("CIDR", s.Alerts.RangeAlerts)
	printAlertLine("Username", s.Alerts.UsernameAlerts)
	printAlertLine("Email", s.Alerts.EmailAlerts)
	fmt.Println()
}

func printQuotaLine(name string, q quotaInfo) {
	label := fmt.Sprintf("    %-12s", name)
	output.Dim.Print(label)
	if q.Limit == 0 {
		output.Dim.Println("--")
		return
	}
	pct := 0
	if q.Limit > 0 {
		pct = (q.Used * 100) / q.Limit
	}
	if pct >= 90 {
		output.Red.Printf("%s", formatCount(int64(q.Used)))
	} else if pct >= 70 {
		output.Yellow.Printf("%s", formatCount(int64(q.Used)))
	} else {
		fmt.Printf("%s", formatCount(int64(q.Used)))
	}
	fmt.Printf(" / %s", formatCount(int64(q.Limit)))
	output.Dim.Printf("  (%s remaining)\n", formatCount(int64(q.Remaining)))
}

func printAlertLine(name string, a alertInfo) {
	label := fmt.Sprintf("    %-12s", name)
	output.Dim.Print(label)
	if a.Limit == 0 {
		output.Dim.Println("--")
		return
	}
	fmt.Printf("%d / %d\n", a.Current, a.Limit)
}
