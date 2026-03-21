package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type emailResponse struct {
	Email         string `json:"email"`
	TotalMessages int64  `json:"totalMessages"`
	FirstSeenAt   int64  `json:"firstSeenAt"`
	LastSeenAt    int64  `json:"lastSeenAt"`
}

func newEmailCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "email <email>",
		Short: "Look up an SMTP recipient email",
		Long: `Check if an email address has been seen as an SMTP recipient in honeypot attacks.

Returns message count and first/last seen dates.

Examples:
  sikker email admin@example.com
  sikker email test@gmail.com --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			email := args[0]

			c := client.New(cfg)
			body, status, _, err := c.Get("/v1/key/email/" + url.PathEscape(email))
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(body)
				return nil
			}

			if status == 404 {
				output.Dim.Printf("\"%s\"", email)
				fmt.Println(" — not found in attack database")
				return nil
			}

			if status != 200 {
				output.Errorf("API error (HTTP %d): %s", status, string(body))
				return fmt.Errorf("API error %d", status)
			}

			var resp emailResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printEmailResult(&resp)
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printEmailResult(r *emailResponse) {
	output.Accent.Printf("\"%s\"", r.Email)
	fmt.Printf(" — ")
	output.Bold.Printf("%s", formatCount(r.TotalMessages))
	fmt.Println(" messages")

	firstSeen := output.FormatEpochAgo(r.FirstSeenAt)
	lastSeen := output.FormatEpochAgo(r.LastSeenAt)
	output.Dim.Print("  First seen: ")
	fmt.Println(firstSeen)
	output.Dim.Print("  Last seen:  ")
	fmt.Println(lastSeen)
}
