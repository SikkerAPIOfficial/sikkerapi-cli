package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

type bulkCheckResponse struct {
	Queried int              `json:"queried"`
	Found   int              `json:"found"`
	Results []bulkCheckEntry `json:"results"`
}

type bulkCheckEntry struct {
	IP              string `json:"ip"`
	Found           bool   `json:"found"`
	ConfidenceLevel *int   `json:"confidenceLevel"`
	CountryCode     *string `json:"countryCode"`
	LastSeen        *int64  `json:"lastSeen"`
}

func newBulkCheckCmd() *cobra.Command {
	var (
		outputFile string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "bulk-check <file>",
		Short: "Check multiple IPs at once",
		Long: `Submit a file of IP addresses for bulk reputation checking.

File format: one IP per line (.txt or .csv). Max 10,000 IPs.

Results are printed to the terminal (first 30) and written to a file.

Examples:
  sikker bulk-check ips.txt
  sikker bulk-check ips.txt -o results.csv
  sikker bulk-check ips.txt --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]

			info, err := os.Stat(filePath)
			if err != nil {
				output.Errorf("Cannot access file: %s", err)
				return err
			}
			if info.Size() > 10*1024*1024 {
				output.Error("File too large (max 10MB)")
				return fmt.Errorf("file too large")
			}

			data, err := os.ReadFile(filePath)
			if err != nil {
				output.Errorf("Cannot read file: %s", err)
				return err
			}

			// Count IPs for user feedback
			lines := strings.Split(string(data), "\n")
			ipCount := 0
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					ipCount++
				}
			}

			if ipCount == 0 {
				output.Error("File contains no IPs")
				return fmt.Errorf("empty file")
			}

			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			output.Dim.Printf("Checking %d IPs...\n", ipCount)

			c := client.New(cfg)
			// Send as plain text body — server parses one IP per line
			body, status, headers, err := c.PostText("/v1/key/bulk-check-inline", data)
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

			var resp bulkCheckResponse
			if err := json.Unmarshal(body, &resp); err != nil {
				output.Errorf("Failed to parse response: %s", err)
				return err
			}

			// Print summary
			fmt.Println()
			output.Dim.Print("Queried: ")
			fmt.Println(resp.Queried)
			output.Dim.Print("Found:   ")
			if resp.Found > 0 {
				output.Red.Println(resp.Found)
			} else {
				output.Green.Println(0)
			}
			fmt.Println()

			// Print results (max 30 to terminal)
			displayLimit := 30
			if len(resp.Results) < displayLimit {
				displayLimit = len(resp.Results)
			}

			foundResults := make([]bulkCheckEntry, 0)
			for _, r := range resp.Results {
				if r.Found {
					foundResults = append(foundResults, r)
				}
			}

			if len(foundResults) > 0 {
				printBulkCheckTable(foundResults, displayLimit)

				if len(foundResults) > 30 {
					fmt.Println()
					output.Dim.Printf("Showing %d of %d found IPs.\n", displayLimit, len(foundResults))
				}
			} else {
				output.Green.Println("No threats found in the submitted IPs.")
			}

			// Write results to file
			if outputFile == "" {
				outputFile = fmt.Sprintf("bulk-check-%s.csv", time.Now().Format("2006-01-02-150405"))
			}

			if err := writeBulkCheckCSV(outputFile, resp.Results); err != nil {
				output.Errorf("Failed to write results: %s", err)
			} else {
				fmt.Println()
				output.Dim.Printf("Full results written to: ")
				fmt.Println(outputFile)
			}

			output.PrintRateLimit(headers, "ratelimit")
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output CSV file path (default: bulk-check-<timestamp>.csv)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func printBulkCheckTable(results []bulkCheckEntry, limit int) {
	// Header
	fmt.Printf("  %s  %s  %s  %s\n",
		output.PadRight("IP", 18),
		output.PadRight("SCORE", 7),
		output.PadRight("COUNTRY", 9),
		"LAST SEEN",
	)
	output.Dim.Printf("  %s\n", strings.Repeat("─", 55))

	for i, r := range results {
		if i >= limit {
			break
		}

		score := "—"
		var coloredScore string
		if r.ConfidenceLevel != nil {
			score = strconv.Itoa(*r.ConfidenceLevel)
			if *r.ConfidenceLevel >= 75 {
				coloredScore = output.Red.Sprint(output.PadRight(score, 7))
			} else if *r.ConfidenceLevel >= 50 {
				coloredScore = output.Yellow.Sprint(output.PadRight(score, 7))
			} else {
				coloredScore = output.Green.Sprint(output.PadRight(score, 7))
			}
		} else {
			coloredScore = output.Dim.Sprint(output.PadRight(score, 7))
		}

		country := "—"
		if r.CountryCode != nil && *r.CountryCode != "" {
			country = *r.CountryCode
		}

		lastSeen := "—"
		if r.LastSeen != nil && *r.LastSeen > 0 {
			lastSeen = output.FormatEpochAgo(*r.LastSeen)
		}

		fmt.Printf("  %s  %s  %s  %s\n",
			output.PadRight(r.IP, 18),
			coloredScore,
			output.PadRight(country, 9),
			lastSeen,
		)
	}
}

func writeBulkCheckCSV(path string, results []bulkCheckEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "ip,found,confidence_level,country_code,last_seen")
	for _, r := range results {
		score := ""
		if r.ConfidenceLevel != nil {
			score = strconv.Itoa(*r.ConfidenceLevel)
		}
		country := ""
		if r.CountryCode != nil {
			country = *r.CountryCode
		}
		lastSeen := ""
		if r.LastSeen != nil && *r.LastSeen > 0 {
			lastSeen = time.UnixMilli(*r.LastSeen).UTC().Format("2006-01-02T15:04:05Z")
		}

		fmt.Fprintf(f, "%s,%t,%s,%s,%s\n", r.IP, r.Found, score, country, lastSeen)
	}

	return nil
}
