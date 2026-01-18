package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	debug       bool
	environment string
	apiKey         string
	organizationID string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "harica",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().StringVarP(&environment, "environment", "e", "production", "Environment to use (production, staging, devel)")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "HARICA API key (can also be set via HARICA_API_KEY or config key api_key)")
	rootCmd.PersistentFlags().StringVar(&organizationID, "organization-id", "", "HARICA Organization ID (can also be set via HARICA_ORGANIZATION_ID or config key organization_id)")

	// Global viper env handling. Precedence is: flags > env > config.
	viper.SetEnvPrefix("HARICA")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	_ = viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	_ = viper.BindPFlag("organization_id", rootCmd.PersistentFlags().Lookup("organization-id"))
}
