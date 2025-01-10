package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/hm-edu/harica/client"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type GenCertConfig struct {
	Domains           []string `mapstructure:"domains"`
	Csr               string   `mapstructure:"csr"`
	TransactionType   string   `mapstructure:"transaction_type"`
	RequesterEmail    string   `mapstructure:"requester_email"`
	RequesterPassword string   `mapstructure:"requester_password"`
	RequesterTOTPSeed string   `mapstructure:"requester_totp_seed"`
	ValidatorEmail    string   `mapstructure:"validator_email"`
	ValidatorPassword string   `mapstructure:"validator_password"`
	ValidatorTOTPSeed string   `mapstructure:"validator_totp_seed"`
}

var (
	genCertConfig GenCertConfig
	configPath    string
	keyMapping    = map[string]string{
		"domains":             "domains",
		"csr":                 "csr",
		"transaction-type":    "transaction_type",
		"requester-email":     "requester_email",
		"requester-password":  "requester_password",
		"requester-totp-seed": "requester_totp-seed",
		"validator-email":     "validator_email",
		"validator-password":  "validator_password",
		"validator-totp-seed": "validator_totp_seed",
	}
)

// genCertCmd represents the genCert command
var genCertCmd = &cobra.Command{
	Use: "gen-cert",
	PreRun: func(cmd *cobra.Command, args []string) {
		viper.SetConfigType("yaml")
		viper.SetConfigName("cert-generator")
		viper.AddConfigPath("/etc/harica/")  // path to look for the config file in
		viper.AddConfigPath("$HOME/harica/") // call multiple times to add many search paths
		viper.AddConfigPath("/opt/harica/")
		viper.AddConfigPath(".") // optionally look for config in the working directory
		if configPath != "" {
			viper.SetConfigFile(configPath)
		}
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				slog.Info("No configuration file found")
			} else {
				slog.Error("Error reading config file", slog.Any("error", err))
				os.Exit(1)
			}
		} else {
			slog.Info("Using config file:", slog.Any("config", viper.ConfigFileUsed()))
		}

		// Unmarshal the config into a struct.
		err := viper.Unmarshal(&genCertConfig)
		if err != nil {
			slog.Error("Error reading config file", slog.Any("error", err))
			os.Exit(1)
		}

		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if !f.Changed && viper.IsSet(f.Name) {
				val := viper.Get(f.Name)
				err = cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
				if err != nil {
					slog.Error("Failed to set flag", slog.Any("error", err))
					os.Exit(1)
				}
			} else if v, ok := keyMapping[f.Name]; !f.Changed && ok && viper.IsSet(v) {
				val := viper.Get(v)
				err = cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
				if err != nil {
					slog.Error("Failed to set flag", slog.Any("error", err))
					os.Exit(1)
				}
			}
		})
	},
	Run: func(cmd *cobra.Command, args []string) {

		requester, err := client.NewClient(genCertConfig.RequesterEmail, genCertConfig.RequesterPassword, genCertConfig.RequesterTOTPSeed, client.WithDebug(debug))
		if err != nil {
			slog.Error("failed to create requester client", slog.Any("error", err))
			os.Exit(1)
		}
		validator, err := client.NewClient(genCertConfig.ValidatorEmail, genCertConfig.ValidatorPassword, genCertConfig.ValidatorTOTPSeed, client.WithDebug(debug))
		if err != nil {
			slog.Error("failed to create validator client", slog.Any("error", err))
			os.Exit(1)
		}

		orgs, err := requester.CheckMatchingOrganization(genCertConfig.Domains)
		if err != nil || len(orgs) == 0 {
			slog.Error("failed to check matching organization", slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("matching organizations", slog.Any("organizations", orgs))

		transaction, err := requester.RequestCertificate(genCertConfig.Domains, genCertConfig.Csr, genCertConfig.TransactionType, orgs[0])
		if err != nil {
			slog.Error("failed to request certificate", slog.Any("error", err))
			os.Exit(1)
		}

		reviews, err := validator.GetPendingReviews()
		if err != nil {
			slog.Error("failed to get pending reviews", slog.Any("error", err))
			os.Exit(1)
		}

		for _, r := range reviews {
			if r.TransactionID == transaction.TransactionID {
				for _, s := range r.ReviewGetDTOs {
					err = validator.ApproveRequest(s.ReviewID, "Auto Approval", s.ReviewValue)
					if err != nil {
						slog.Error("failed to approve request", slog.Any("error", err))
						os.Exit(1)
					}
				}
				break
			}
		}
		cert, err := requester.GetCertificate(transaction.TransactionID)
		if err != nil {
			slog.Error("failed to get certificate", slog.Any("error", err))
			os.Exit(1)
		}
		fmt.Print(cert.PemBundle)
	},
}

func init() {
	rootCmd.AddCommand(genCertCmd)
	genCertCmd.Flags().StringSlice("domains", []string{}, "Domains to request certificate for")
	genCertCmd.Flags().String("csr", "", "CSR to request certificate with")
	genCertCmd.Flags().StringP("transaction-type", "t", "DV", "Transaction type to request certificate with")
	genCertCmd.Flags().String("requester-email", "", "Email of requester")
	genCertCmd.Flags().String("requester-password", "", "Password of requester")
	genCertCmd.Flags().String("requester-totp-seed", "", "TOTP seed of requester")
	genCertCmd.Flags().String("validator-email", "", "Email of validator")
	genCertCmd.Flags().String("validator-password", "", "Password of validator")
	genCertCmd.Flags().String("validator-totp-seed", "", "TOTP seed of validator")

	for k, v := range keyMapping {
		err := viper.BindPFlag(v, genCertCmd.Flags().Lookup(k))
		if err != nil {
			slog.Error("Failed to bind flag", slog.Any("error", err))
			os.Exit(1)
		}
	}

	for _, s := range []string{"domains", "csr", "requester-email", "requester-password", "validator-email", "validator-password", "validator-totp-seed"} {
		err := genCertCmd.MarkFlagRequired(s)
		if err != nil {
			slog.Error("Failed to mark flag required", slog.Any("error", err))
			os.Exit(1)
		}
	}

	genCertCmd.Flags().StringVar(&configPath, "config", "", "config file (default is cert-generator.yaml)")
}
