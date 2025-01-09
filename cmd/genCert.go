package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/hm-edu/harica/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type GenCertConfig struct {
	Domains           []string `mapstructure:"domains" validate:"required"`
	Csr               string   `mapstructure:"csr" validate:"required"`
	TransactionType   string   `mapstructure:"transaction_type" validate:"required"`
	RequesterEmail    string   `mapstructure:"requester_email" validate:"required"`
	RequesterPassword string   `mapstructure:"requester_password" validate:"required"`
	RequesterTOTPSeed string   `mapstructure:"requester_totp_seed"`
	ValidatorEmail    string   `mapstructure:"validator_email" validate:"required"`
	ValidatorPassword string   `mapstructure:"validator_password" validate:"required"`
	ValidatorTOTPSeed string   `mapstructure:"validator_totp_seed" validate:"required"`
}

var (
	genCertConfig GenCertConfig
	configPath    string
)

// genCertCmd represents the genCert command
var genCertCmd = &cobra.Command{
	Use: "gen-cert",
	Run: func(cmd *cobra.Command, args []string) {
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
		}

		viper.BindPFlags(cmd.Flags())

		// Unmarshal the config into a struct.
		err := viper.Unmarshal(&genCertConfig)
		if err != nil {
			slog.Error("Error reading config file", slog.Any("error", err))
			os.Exit(1)
		}
		validate := validator.New()
		if err := validate.Struct(&genCertConfig); err != nil {
			slog.Error(fmt.Sprintf("Missing required attributes: \n%v\n", err))
			os.Exit(1)
		}
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
	genCertCmd.PersistentFlags().StringSlice("domains", []string{}, "Domains to request certificate for")
	genCertCmd.PersistentFlags().String("csr", "", "CSR to request certificate with")
	genCertCmd.PersistentFlags().StringP("transaction-type", "t", "DV", "Transaction type to request certificate with")
	genCertCmd.PersistentFlags().String("requester-email", "", "Email of requester")
	genCertCmd.PersistentFlags().String("requester-password", "", "Password of requester")
	genCertCmd.PersistentFlags().String("requester-totp-seed", "", "TOTP seed of requester")
	genCertCmd.PersistentFlags().String("validator-email", "", "Email of validator")
	genCertCmd.PersistentFlags().String("validator-password", "", "Password of validator")
	genCertCmd.PersistentFlags().String("validator-totp-seed", "", "TOTP seed of validator")

	viper.BindPFlag("domains", genCertCmd.PersistentFlags().Lookup("domains"))
	viper.BindPFlag("csr", genCertCmd.PersistentFlags().Lookup("csr"))
	viper.BindPFlag("transaction_type", genCertCmd.PersistentFlags().Lookup("transaction-type"))
	viper.BindPFlag("requester_email", genCertCmd.PersistentFlags().Lookup("requester-email"))
	viper.BindPFlag("requester_password", genCertCmd.PersistentFlags().Lookup("requester-password"))
	viper.BindPFlag("requester_totp_seed", genCertCmd.PersistentFlags().Lookup("requester-totp-seed"))
	viper.BindPFlag("validator_email", genCertCmd.PersistentFlags().Lookup("validator-email"))
	viper.BindPFlag("validator_password", genCertCmd.PersistentFlags().Lookup("validator-password"))
	viper.BindPFlag("validator_totp_seed", genCertCmd.PersistentFlags().Lookup("validator-totp-seed"))

	genCertCmd.PersistentFlags().StringVar(&configPath, "config", "", "config file (default is $HOME/harica/cert-generator.yaml)")
}
