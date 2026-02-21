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

const defaultCollection = "sikker-threat-intel"

func newTaxiiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "taxii",
		Short: "TAXII 2.1 / STIX threat feeds",
		Long: `Query TAXII 2.1 threat intelligence feeds from SikkerAPI.

Examples:
  sikker taxii list --limit 10
  sikker taxii get 1.2.3.4`,
	}

	cmd.AddCommand(newTaxiiListCmd())
	cmd.AddCommand(newTaxiiGetCmd())

	return cmd
}

func newTaxiiListCmd() *cobra.Command {
	var (
		limit      int
		offset     int
		addedAfter string
		collection string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List STIX objects from a TAXII collection",
		Long: `Fetch STIX 2.1 objects from a TAXII collection.

Examples:
  sikker taxii list --limit 100
  sikker taxii list --added-after 2026-02-01T00:00:00Z --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			params := map[string]string{}
			if limit > 0 {
				params["limit"] = strconv.Itoa(limit)
			}
			if offset > 0 {
				params["offset"] = strconv.Itoa(offset)
			}
			if addedAfter != "" {
				params["added_after"] = addedAfter
			}

			path := fmt.Sprintf("/taxii2/collections/%s/objects/", collection)
			c := client.New(cfg)
			body, status, headers, err := c.Get(path + client.BuildQuery(params))
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

			printTaxiiBundle(body)
			output.PrintRateLimit(headers, "taxii")
			return nil
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of objects")
	cmd.Flags().IntVar(&offset, "offset", 0, "Pagination offset")
	cmd.Flags().StringVar(&addedAfter, "added-after", "", "Only objects added after this ISO 8601 timestamp")
	cmd.Flags().StringVar(&collection, "collection", defaultCollection, "TAXII collection ID")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

func newTaxiiGetCmd() *cobra.Command {
	var (
		collection string
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "get <ip>",
		Short: "Get STIX object for a specific IP",
		Long: `Retrieve the STIX 2.1 indicator for a specific IP address.

Examples:
  sikker taxii get 1.2.3.4
  sikker taxii get 1.2.3.4 --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				output.Errorf("Failed to load config: %s", err)
				return err
			}
			client.RequireKey(cfg)

			ip := args[0]
			path := fmt.Sprintf("/taxii2/collections/%s/objects/%s/", collection, ip)

			c := client.New(cfg)
			body, status, headers, err := c.Get(path)
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

			printStixObject(body)
			output.PrintRateLimit(headers, "taxii")
			return nil
		},
	}

	cmd.Flags().StringVar(&collection, "collection", defaultCollection, "TAXII collection ID")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON")

	return cmd
}

// printTaxiiBundle prints a human-readable summary of a STIX bundle.
func printTaxiiBundle(data []byte) {
	var bundle map[string]interface{}
	if err := json.Unmarshal(data, &bundle); err != nil {
		output.PrintJSON(data)
		return
	}

	objects, ok := bundle["objects"].([]interface{})
	if !ok || len(objects) == 0 {
		output.Dim.Println("No objects in bundle.")
		return
	}

	output.Accent.Printf("STIX Bundle")
	fmt.Printf(" — %d object(s)\n\n", len(objects))

	for i, obj := range objects {
		m, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}

		stixType := getString(m, "type")
		stixID := getString(m, "id")
		name := getString(m, "name")
		created := getString(m, "created")
		modified := getString(m, "modified")

		output.Dim.Printf("  [%d] ", i+1)
		output.Bold.Printf("%s", stixType)
		if name != "" {
			fmt.Printf(" — %s", name)
		}
		fmt.Println()

		output.Dim.Printf("       ID: ")
		fmt.Println(stixID)
		if created != "" {
			output.Dim.Printf("       Created:  ")
			fmt.Println(output.FormatTimeAgo(created))
		}
		if modified != "" {
			output.Dim.Printf("       Modified: ")
			fmt.Println(output.FormatTimeAgo(modified))
		}

		// Show pattern if it's an indicator
		if pattern := getString(m, "pattern"); pattern != "" {
			output.Dim.Printf("       Pattern:  ")
			fmt.Println(pattern)
		}

		// Show labels
		if labels, ok := m["labels"].([]interface{}); ok && len(labels) > 0 {
			var labelStrs []string
			for _, l := range labels {
				if s, ok := l.(string); ok {
					labelStrs = append(labelStrs, s)
				}
			}
			output.Dim.Printf("       Labels:   ")
			fmt.Println(strings.Join(labelStrs, ", "))
		}

		fmt.Println()
	}
}

// printStixObject prints a human-readable summary of a single STIX object.
func printStixObject(data []byte) {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		output.PrintJSON(data)
		return
	}

	stixType := getString(m, "type")
	stixID := getString(m, "id")
	name := getString(m, "name")
	created := getString(m, "created")
	modified := getString(m, "modified")
	description := getString(m, "description")

	output.Bold.Printf("%s", stixType)
	if name != "" {
		fmt.Printf(" — %s", name)
	}
	fmt.Println()

	output.Dim.Print("  ID:       ")
	fmt.Println(stixID)

	if created != "" {
		output.Dim.Print("  Created:  ")
		fmt.Println(output.FormatTimeAgo(created))
	}
	if modified != "" {
		output.Dim.Print("  Modified: ")
		fmt.Println(output.FormatTimeAgo(modified))
	}

	if pattern := getString(m, "pattern"); pattern != "" {
		output.Dim.Print("  Pattern:  ")
		fmt.Println(pattern)
	}

	if labels, ok := m["labels"].([]interface{}); ok && len(labels) > 0 {
		var labelStrs []string
		for _, l := range labels {
			if s, ok := l.(string); ok {
				labelStrs = append(labelStrs, s)
			}
		}
		output.Dim.Print("  Labels:   ")
		fmt.Println(strings.Join(labelStrs, ", "))
	}

	if description != "" {
		output.Dim.Print("  Desc:     ")
		fmt.Println(description)
	}
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
