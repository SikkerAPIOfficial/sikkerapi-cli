package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type bulkReportResponse struct {
	Total    int              `json:"total"`
	Accepted int             `json:"accepted"`
	Rejected int             `json:"rejected"`
	Errors   []bulkReportErr `json:"errors"`
}

type bulkReportErr struct {
	Row   int    `json:"row"`
	IP    string `json:"ip"`
	Error string `json:"error"`
}

func newBulkReportCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "bulk-report <file>",
		Short: "Submit abuse reports in bulk",
		Long: `Upload a CSV or JSON file of abuse reports to SikkerAPI.

CSV format (header optional):
  IP,Category,Protocol,Comment
  1.2.3.4,brute_force,ssh,Attack attempt
  5.6.7.8,3,http,

JSON format:
  {"reports": [{"ip": "1.2.3.4", "category": "brute_force", "protocol": "ssh"}]}

Max 10,000 reports per file. Max 2MB.

Examples:
  sikker bulk-report reports.csv
  sikker bulk-report reports.json --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			info, err := os.Stat(filePath)
			if err != nil {
				output.Errorf("Cannot access file: %s", err)
				return err
			}
			if info.Size() > 2*1024*1024 {
				output.Error("File too large (max 2MB)")
				return fmt.Errorf("file too large")
			}

			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			c := client.New(cfg)
			var respBody []byte
			var status int
			var headers http.Header

			if strings.HasSuffix(strings.ToLower(filePath), ".json") {
				// JSON file — read and POST as application/json
				data, err := os.ReadFile(filePath)
				if err != nil {
					output.Errorf("Cannot read file: %s", err)
					return err
				}
				respBody, status, headers, err = c.Post("/v1/key/bulk-report", data)
				if err != nil {
					output.Errorf("Error: %s", err)
					return err
				}
			} else {
				// CSV file — upload as multipart/form-data
				respBody, status, headers, err = c.PostMultipart("/v1/key/bulk-report", "file", filePath)
				if err != nil {
					output.Errorf("Error: %s", err)
					return err
				}
			}

			if jsonOutput {
				output.PrintJSON(respBody)
				return nil
			}

			if status != 200 {
				output.Errorf("API error (HTTP %d): %s", status, string(respBody))
				return fmt.Errorf("API error %d", status)
			}

			var resp bulkReportResponse
			if err := json.Unmarshal(respBody, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			printBulkReportResult(&resp)
			output.PrintRateLimit(headers, "report")
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printBulkReportResult(r *bulkReportResponse) {
	output.Dim.Print("Total:    ")
	fmt.Println(r.Total)
	output.Dim.Print("Accepted: ")
	output.Green.Println(r.Accepted)
	output.Dim.Print("Rejected: ")
	if r.Rejected > 0 {
		output.Red.Println(r.Rejected)
	} else {
		fmt.Println(0)
	}

	if len(r.Errors) > 0 {
		fmt.Println()
		output.Red.Println("Errors:")
		for _, e := range r.Errors {
			fmt.Printf("  Row %d", e.Row)
			if e.IP != "" {
				fmt.Printf(" (%s)", e.IP)
			}
			fmt.Printf(": %s\n", e.Error)
		}
	}
}
