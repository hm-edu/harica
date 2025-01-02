package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/hm-edu/harica/client"
	"github.com/spf13/cobra"
)

type GenCertConfig struct {
	domains           []string
	csr               string
	transactionType   string
	requesterEmail    string
	requesterPassword string
	requesterTOTPSeed string
	validatorEmail    string
	validatorPassword string
	validatorTOTPSeed string
}

var (
	genCertConfig GenCertConfig
)

// genCertCmd represents the genCert command
var genCertCmd = &cobra.Command{
	Use: "gen-cert",
	Run: func(cmd *cobra.Command, args []string) {

		requester, err := client.NewClient(genCertConfig.requesterEmail, genCertConfig.requesterPassword, genCertConfig.requesterTOTPSeed, client.WithDebug(debug))
		if err != nil {
			slog.Error("failed to create requester client", slog.Any("error", err))
			os.Exit(1)
		}
		validator, err := client.NewClient(genCertConfig.validatorEmail, genCertConfig.validatorPassword, genCertConfig.validatorTOTPSeed, client.WithDebug(debug))
		if err != nil {
			slog.Error("failed to create validator client", slog.Any("error", err))
			os.Exit(1)
		}

		orgs, err := requester.CheckMatchingOrganization(genCertConfig.domains)
		if err != nil || len(orgs) == 0 {
			slog.Error("failed to check matching organization", slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("matching organizations", slog.Any("organizations", orgs))

		transaction, err := requester.RequestCertificate(genCertConfig.domains, genCertConfig.csr, genCertConfig.transactionType, orgs[0])
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
	genCertCmd.Flags().StringSliceVar(&genCertConfig.domains, "domains", []string{}, "Domains to request certificate for")
	genCertCmd.Flags().StringVar(&genCertConfig.csr, "csr", "", "CSR to request certificate with")
	genCertCmd.Flags().StringVarP(&genCertConfig.transactionType, "transaction-type", "t", "DV", "Transaction type to request certificate with")
	genCertCmd.Flags().StringVar(&genCertConfig.requesterEmail, "requester-email", "", "Email of requester")
	genCertCmd.Flags().StringVar(&genCertConfig.requesterPassword, "requester-password", "", "Password of requester")
	genCertCmd.Flags().StringVar(&genCertConfig.requesterTOTPSeed, "requester-totp-seed", "", "TOTP seed of requester")
	genCertCmd.Flags().StringVar(&genCertConfig.validatorEmail, "validator-email", "", "Email of validator")
	genCertCmd.Flags().StringVar(&genCertConfig.validatorPassword, "validator-password", "", "Password of validator")
	genCertCmd.Flags().StringVar(&genCertConfig.validatorTOTPSeed, "validator-totp-seed", "", "TOTP seed of validator")

	genCertCmd.MarkFlagRequired("domains")             //nolint:errcheck
	genCertCmd.MarkFlagRequired("csr")                 //nolint:errcheck
	genCertCmd.MarkFlagRequired("requester-email")     //nolint:errcheck
	genCertCmd.MarkFlagRequired("requester-password")  //nolint:errcheck
	genCertCmd.MarkFlagRequired("requester-totp-seed") //nolint:errcheck
	genCertCmd.MarkFlagRequired("validator-email")     //nolint:errcheck
	genCertCmd.MarkFlagRequired("validator-password")  //nolint:errcheck
	genCertCmd.MarkFlagRequired("validator-totp-seed") //nolint:errcheck
}
