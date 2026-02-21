package cmd

import (
	"fmt"
	"strings"

	"github.com/sikkerapi/sikker-cli/internal/config"
	"github.com/sikkerapi/sikker-cli/internal/output"
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth <api-key>",
		Short: "Save your SikkerAPI key",
		Long:  "Stores your API key locally at ~/.config/sikkerapi/config.json",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.TrimSpace(args[0])

			if !strings.HasPrefix(key, "sk_") {
				output.Error("Invalid API key format. Keys start with sk_")
				return fmt.Errorf("invalid key format")
			}

			cfg, _ := config.Load()
			cfg.APIKey = key

			if err := config.Save(cfg); err != nil {
				output.Errorf("Failed to save config: %s", err)
				return err
			}

			output.Success("API key saved.")
			fmt.Printf("Key: %s...%s\n", key[:6], key[len(key)-4:])
			return nil
		},
	}
}
