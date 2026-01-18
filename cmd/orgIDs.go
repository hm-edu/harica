package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hm-edu/harica/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var orgIDsCmd = &cobra.Command{
	Use:   "org-ids",
	Short: "List organization IDs available to an API key",
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := viper.GetString("api_key")
		if strings.TrimSpace(apiKey) == "" {
			slog.Error("api key is required; provide --api-key, HARICA_API_KEY, or config key api_key")
			os.Exit(1)
		}

		enterprises, raw, err := client.ListCMv1Enterprises(client.BaseURLProduction, apiKey, debug)
		if err != nil {
			if len(raw) > 0 {
				fmt.Fprintln(os.Stderr, string(raw))
			}
			slog.Error("failed to list enterprises", slog.Any("error", err))
			os.Exit(1)
		}

		seen := map[string]struct{}{}
		for _, e := range enterprises {
			id := strings.TrimSpace(e.OrganizationID)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			fmt.Println(id)
		}

		if len(seen) == 0 {
			slog.Error("no organization ids found for this api key")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(orgIDsCmd)
}
