package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	debug       bool
	environment string
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
}
