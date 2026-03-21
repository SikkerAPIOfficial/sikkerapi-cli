package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type usernameAlertEntry struct {
	ID                 string  `json:"id"`
	Username           string  `json:"username"`
	Label              *string `json:"label"`
	Enabled            bool    `json:"enabled"`
	EmailNotifications bool    `json:"emailNotifications"`
	LastAlertedAt      *string `json:"lastAlertedAt"`
	TotalAlerts        int     `json:"totalAlerts"`
	MatchCount         int64   `json:"matchCount"`
	CreatedAt          string  `json:"createdAt"`
}

type usernameAlertListResponse struct {
	Alerts []usernameAlertEntry `json:"alerts"`
}

func newUsernameAlertCmd() *cobra.Command {
	var (
		label      string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "username-alert [username]",
		Short: "Manage username alerts",
		Long: `Add, list, or delete username alerts.

Monitor brute-force usernames. When a username you're monitoring appears
in attack data, you'll be notified.

Examples:
  sikker username-alert admin
  sikker username-alert deploy -l "CI/CD user"
  sikker username-alert list
  sikker username-alert delete <alert-id>`,
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

			reqBody := map[string]string{"username": args[0]}
			if label != "" {
				reqBody["label"] = label
			}
			bodyBytes, _ := json.Marshal(reqBody)

			body, status, _, err := c.Post("/v1/key/username-alerts", bodyBytes)
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status == 201 {
				var alert usernameAlertEntry
				json.Unmarshal(body, &alert)
				output.Green.Printf("Alert created for \"%s\"", alert.Username)
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

	cmd.AddCommand(newUsernameAlertListCmd())
	cmd.AddCommand(newUsernameAlertDeleteCmd())

	return cmd
}

func newUsernameAlertListCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all username alerts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/key/username-alerts")
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

			var resp usernameAlertListResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			if len(resp.Alerts) == 0 {
				output.Dim.Println("No username alerts configured.")
				return nil
			}

			fmt.Println()
			for _, a := range resp.Alerts {
				printAlertRow(a.Username, a.ID, a.Label, a.Enabled, a.TotalAlerts, a.MatchCount, a.CreatedAt)
			}
			fmt.Println()
			output.Dim.Printf("%d alert(s)\n", len(resp.Alerts))

			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")
	return cmd
}

func newUsernameAlertDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <alert-id>",
		Short: "Delete a username alert",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return deleteAlert("/v1/key/username-alerts", args[0], "Username")
		},
	}
}
