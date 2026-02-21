package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type reportRequest struct {
	IP       string `json:"ip"`
	Category string `json:"category"`
	Protocol string `json:"protocol,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

type reportResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func newReportCmd() *cobra.Command {
	var (
		category   string
		protocol   string
		comment    string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "report <ip>",
		Short: "Submit an abuse report",
		Long: `Report a malicious IP address to SikkerAPI.

Categories: brute_force, port_scan, ddos, web_exploit, sql_injection,
phishing, spam, bad_bot, exploited_host, malware, dns_abuse, open_proxy,
iot_targeted, spoofing, fraud, other (or numeric 1-16)

Examples:
  sikker report 1.2.3.4 --category brute_force --protocol ssh
  sikker report 5.6.7.8 --category 3 --comment "repeated login attempts"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if category == "" {
				output.Error("--category is required")
				return fmt.Errorf("missing required flag: --category")
			}

			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			req := reportRequest{
				IP:       args[0],
				Category: category,
				Protocol: protocol,
				Comment:  comment,
			}

			body, err := json.Marshal(req)
			if err != nil {
				output.Errorf("Failed to build request: %s", err)
				return err
			}

			c := client.New(cfg)
			respBody, status, err := c.Post("/v1/key/report", body)
			if err != nil {
				output.Errorf("Error: %s", err)
				return err
			}

			if jsonOutput {
				output.PrintJSON(respBody)
				return nil
			}

			if status != 200 {
				output.Errorf("API error (HTTP %d): %s", status, string(respBody))
				return fmt.Errorf("API error %d", status)
			}

			var resp reportResponse
			if err := json.Unmarshal(respBody, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			if resp.Success {
				output.Success(fmt.Sprintf("Report submitted for %s (category: %s)", args[0], category))
			} else {
				output.Errorf("Report rejected: %s", resp.Error)
				return fmt.Errorf("report rejected")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&category, "category", "", "Attack category (name or number 1-16, required)")
	cmd.Flags().StringVar(&protocol, "protocol", "", "Protocol (e.g. ssh, http)")
	cmd.Flags().StringVar(&comment, "comment", "", "Free text comment (max 1000 chars)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}
