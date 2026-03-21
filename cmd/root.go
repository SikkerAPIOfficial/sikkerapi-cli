package cmd

import (
	"github.com/sikkerapi/sikker-cli/internal/client"
	"github.com/spf13/cobra"
)

func NewRootCmd(version string) *cobra.Command {
	client.SetVersion(version)

	rootCmd := &cobra.Command{
		Use:   "sikker",
		Short: "SikkerAPI CLI — IP reputation, blacklists, reports, and TAXII feeds",
		Long: `sikker is the official CLI tool for SikkerAPI.

Look up IP reputation data, download threat blacklists, submit abuse
reports, and pull TAXII/STIX feeds — all from your terminal.

Get started:
  sikker auth <your-api-key>
  sikker check 1.2.3.4
  sikker blacklist --score-min 75 --plaintext`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newAuthCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newBlacklistCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newBulkReportCmd())
	rootCmd.AddCommand(newTaxiiCmd())
	rootCmd.AddCommand(newUsernameCmd())
	rootCmd.AddCommand(newEmailCmd())
	rootCmd.AddCommand(newBulkCheckCmd())
	rootCmd.AddCommand(newIpAlertCmd())
	rootCmd.AddCommand(newCidrAlertCmd())
	rootCmd.AddCommand(newUsernameAlertCmd())
	rootCmd.AddCommand(newEmailAlertCmd())

	return rootCmd
}
