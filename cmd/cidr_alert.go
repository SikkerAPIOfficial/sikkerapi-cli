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

type rangeAlertEntry struct {
	ID                 string  `json:"id"`
	CIDR               string  `json:"cidr"`
	NetworkAddress     string  `json:"networkAddress"`
	PrefixLength       int     `json:"prefixLength"`
	Label              *string `json:"label"`
	Enabled            bool    `json:"enabled"`
	EmailNotifications bool    `json:"emailNotifications"`
	LastAlertedAt      *string `json:"lastAlertedAt"`
	TotalAlerts        int     `json:"totalAlerts"`
	UniqueMatches      int64   `json:"uniqueMatches"`
	CreatedAt          string  `json:"createdAt"`
}

type rangeAlertListResponse struct {
	Alerts []rangeAlertEntry `json:"alerts"`
}

func newCidrAlertCmd() *cobra.Command {
	var (
		label      string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "cidr-alert [cidr]",
		Short: "Manage CIDR range alerts",
		Long: `Add, list, or delete CIDR range alerts.

Monitor entire IP ranges for attacker activity. When any IP in the range
appears in attack data, you'll be notified.

Examples:
  sikker cidr-alert 192.168.1.0/24
  sikker cidr-alert 10.0.0.0/16 -l "office network"
  sikker cidr-alert list
  sikker cidr-alert delete <alert-id>`,
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

			reqBody := map[string]string{"cidr": args[0]}
			if label != "" {
				reqBody["label"] = label
			}
			bodyBytes, _ := json.Marshal(reqBody)

			body, status, _, err := c.Post("/v1/key/range-alerts", bodyBytes)
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status == 201 {
				var alert rangeAlertEntry
				json.Unmarshal(body, &alert)
				output.Green.Printf("Alert created for %s", alert.CIDR)
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

	cmd.AddCommand(newCidrAlertListCmd())
	cmd.AddCommand(newCidrAlertDeleteCmd())

	return cmd
}

func newCidrAlertListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all CIDR range alerts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/key/range-alerts")
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

			var resp rangeAlertListResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			if len(resp.Alerts) == 0 {
				output.Dim.Println("No CIDR alerts configured.")
				return nil
			}

			fmt.Println()
			for _, a := range resp.Alerts {
				if a.Enabled {
					output.Accent.Printf("  %s", a.CIDR)
				} else {
					output.Dim.Printf("  %s (disabled)", a.CIDR)
				}
				if a.Label != nil && *a.Label != "" {
					fmt.Printf("  %s", *a.Label)
				}
				fmt.Println()

				output.Dim.Printf("    ID: %s", a.ID)
				if a.TotalAlerts > 0 {
					fmt.Printf("  |  ")
					output.Yellow.Printf("%d alerts", a.TotalAlerts)
				}
				if a.UniqueMatches > 0 {
					fmt.Printf("  |  %s unique IPs matched", formatCount(a.UniqueMatches))
				}
				if idx := strings.Index(a.CreatedAt, "T"); idx > 0 {
					fmt.Printf("  |  created %s", a.CreatedAt[:idx])
				}
				fmt.Println()
			}
			fmt.Println()
			output.Dim.Printf("%d alert(s)\n", len(resp.Alerts))

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	return cmd
}

func newCidrAlertDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <alert-id>",
		Short: "Delete a CIDR range alert",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteAlert("/v1/key/range-alerts", args[0], "CIDR")
		},
	}
}
