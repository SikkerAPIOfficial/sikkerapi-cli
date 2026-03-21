package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type ipAlertEntry struct {
	ID                 string  `json:"id"`
	IP                 string  `json:"ip"`
	Label              *string `json:"label"`
	Enabled            bool    `json:"enabled"`
	EmailNotifications bool    `json:"emailNotifications"`
	LastAlertedAt      *string `json:"lastAlertedAt"`
	TotalAlerts        int     `json:"totalAlerts"`
	MatchCount         int64   `json:"matchCount"`
	CreatedAt          string  `json:"createdAt"`
}

type ipAlertListResponse struct {
	Alerts []ipAlertEntry `json:"alerts"`
}

func newIpAlertCmd() *cobra.Command {
	var (
		label      string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "ip-alert [ip]",
		Short: "Manage IP alerts",
		Long: `Add, list, or delete IP address alerts.

When an IP you're monitoring appears in attack data, you'll be notified.

Examples:
  sikker ip-alert 1.2.3.4
  sikker ip-alert 1.2.3.4 -l "production server"
  sikker ip-alert list
  sikker ip-alert delete <alert-id>`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)

			reqBody := map[string]string{"ip": args[0]}
			if label != "" {
				reqBody["label"] = label
			}
			bodyBytes, _ := json.Marshal(reqBody)

			body, status, _, err := c.Post("/v1/key/ip-alerts", bodyBytes)
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status == 201 {
				var alert ipAlertEntry
				json.Unmarshal(body, &alert)
				output.Green.Printf("Alert created for %s", alert.IP)
				if alert.Label != nil && *alert.Label != "" {
					fmt.Printf(" (%s)", *alert.Label)
				}
				fmt.Println()
				output.Dim.Printf("  ID: %s\n", alert.ID)
				return nil
			}

			printAPIError(body, status)
			return fmt.Errorf("API error %d", status)
		},
	}

	cmd.Flags().StringVarP(&label, "label", "l", "", "Label for the alert")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	cmd.AddCommand(newIpAlertListCmd())
	cmd.AddCommand(newIpAlertDeleteCmd())

	return cmd
}

func newIpAlertListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all IP alerts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/key/ip-alerts")
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

			var resp ipAlertListResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			if len(resp.Alerts) == 0 {
				output.Dim.Println("No IP alerts configured.")
				return nil
			}

			fmt.Println()
			for _, a := range resp.Alerts {
				printAlertRow(a.IP, a.ID, a.Label, a.Enabled, a.TotalAlerts, a.MatchCount, a.CreatedAt)
			}
			fmt.Println()
			output.Dim.Printf("%d alert(s)\n", len(resp.Alerts))

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	return cmd
}

func newIpAlertDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <alert-id>",
		Short: "Delete an IP alert",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteAlert("/v1/key/ip-alerts", args[0], "IP")
		},
	}
}

// Shared helpers used by all alert commands

func printAlertRow(value, id string, label *string, enabled bool, totalAlerts int, matchCount int64, createdAt string) {
	if enabled {
		output.Accent.Printf("  %s", value)
	} else {
		output.Dim.Printf("  %s (disabled)", value)
	}
	if label != nil && *label != "" {
		fmt.Printf("  %s", *label)
	}
	fmt.Println()

	output.Dim.Printf("    ID: %s", id)
	if totalAlerts > 0 {
		fmt.Printf("  |  ")
		output.Yellow.Printf("%d alerts", totalAlerts)
	}
	if matchCount > 0 {
		fmt.Printf("  |  %s matches", formatCount(matchCount))
	}
	// Show created date (trim after T for readability)
	if idx := strings.Index(createdAt, "T"); idx > 0 {
		fmt.Printf("  |  created %s", createdAt[:idx])
	}
	fmt.Println()
}

func deleteAlert(basePath, alertID, typeName string) error {
	cfg, err := config.Load()
	if err != nil {
		output.Errorf("Failed to load config: %s", err)
		return err
	}
	client.RequireKey(cfg)

	c := client.New(cfg)
	body, status, _, err := c.Delete(basePath + "/" + alertID)
	if err != nil {
		output.Errorf("Error: %s", err)
		return err
	}

	if status == 200 {
		output.Green.Printf("%s alert deleted.\n", typeName)
		return nil
	}

	printAPIError(body, status)
	return fmt.Errorf("API error %d", status)
}

func printAPIError(body []byte, status int) {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		output.Errorf("%s", errResp.Error)
	} else {
		output.Errorf("API error (HTTP %d): %s", status, string(body))
	}
}
