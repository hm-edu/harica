package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/hm-edu/harica/client"
	"github.com/hm-edu/harica/models"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type GenCertSmimeConfig struct {
	Csr               string `mapstructure:"csr"`
	CertType          string `mapstructure:"cert_type"`
	RequesterEmail    string `mapstructure:"requester_email"`
	RequesterPassword string `mapstructure:"requester_password"`
	RequesterTOTPSeed string `mapstructure:"requester_totp_seed"`
	ValidatorEmail    string `mapstructure:"validator_email"`
	ValidatorPassword string `mapstructure:"validator_password"`
	ValidatorTOTPSeed string `mapstructure:"validator_totp_seed"`
	//SMIME
	Email        string `mapstructure:"email"`
	FriendlyName string `mapstructure:"friendly_name"`
	GivenName    string `mapstructure:"given_name"`
	SurName      string `mapstructure:"sur_name"`
}

var (
	genCertSmimeConfig GenCertSmimeConfig
	configPathSmime    string
	keyMappingSmime    = map[string]string{
		"csr":                 "csr",
		"cert-type":           "cert_type",
		"requester-email":     "requester_email",
		"requester-password":  "requester_password",
		"requester-totp-seed": "requester_totp_seed",
		"validator-email":     "validator_email",
		"validator-password":  "validator_password",
		"validator-totp-seed": "validator_totp_seed",
		"email":               "email",
		"friendly-name":       "friendly_name",
		"given-name":          "given_name",
		"sur-name":            "sur_name",
	}
)

// genCertCmd represents the genCert command
var genCertSmimeCmd = &cobra.Command{
	Use: "smime",
	PreRun: func(cmd *cobra.Command, args []string) {
		viper.SetConfigType("yaml")
		viper.SetConfigName("cert-generator")
		viper.AddConfigPath("/etc/harica/")  // path to look for the config file in
		viper.AddConfigPath("$HOME/harica/") // call multiple times to add many search paths
		viper.AddConfigPath("/opt/harica/")
		viper.AddConfigPath(".") // optionally look for config in the working directory
		if configPathSmime != "" {
			viper.SetConfigFile(configPathSmime)
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
		err := viper.Unmarshal(&genCertSmimeConfig)
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
			} else if v, ok := keyMappingSmime[f.Name]; !f.Changed && ok && viper.IsSet(v) {
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
		// improve
		if len(genCertSmimeConfig.Email) == 0 {
			slog.Error("'emails' is required at the moment.")
			os.Exit(1)
		}

		genCertSmimeConfig.Csr = strings.ReplaceAll(genCertSmimeConfig.Csr, "\\n", "\n")
		requester, err := client.NewClient(genCertSmimeConfig.RequesterEmail, genCertSmimeConfig.RequesterPassword, genCertSmimeConfig.RequesterTOTPSeed, client.WithDebug(debug))
		if err != nil {
			slog.Error("failed to create requester client", slog.Any("error", err))
			os.Exit(1)
		}

		// get domain from provided email address
		at := strings.LastIndex(genCertSmimeConfig.Email, "@")
		var orgs []models.OrganizationResponse
		if at >= 0 {
			domain := []string{genCertSmimeConfig.Email[at+1:]}
			slog.Info("Email Domain:", slog.Any("domain", domain))
			orgs, err = requester.CheckMatchingOrganization(domain)
			if err != nil || len(orgs) == 0 {
				slog.Error("failed to check matching organization", slog.Any("error", err))
				os.Exit(1)
			}
			slog.Debug("matching organizations", slog.Any("organizations", orgs))
		} else {
			slog.Error("Invalid email address provided.", slog.Any("address", genCertSmimeConfig.Email))
			os.Exit(1)
		}

		// build fake bulk request with sinlge user
		// it looks like the API still does not fully support requesting a single SMIME certificate
		// the request endpoint exists but no review/validation endpoint - atleast missing in API description
		var smimeBulk models.SmimeBulkRequest
		smimeBulk = models.SmimeBulkRequest{
			FriendlyName:   genCertSmimeConfig.FriendlyName,
			Email:          genCertSmimeConfig.Email,
			Email2:         "",
			Email3:         "",
			GivenName:      genCertSmimeConfig.GivenName,
			Surname:        genCertSmimeConfig.SurName,
			PickupPassword: "",
			CertType:       genCertSmimeConfig.CertType,
			CSR:            genCertSmimeConfig.Csr,
		}
		slog.Debug("CSR logged:", slog.Any("csr", smimeBulk.CSR))
		transaction, err := requester.RequestSmimeBulkCertificates(orgs[0].ID, smimeBulk)
		if err != nil {
			slog.Error("failed to request certificate", slog.Any("error", err))
			os.Exit(1)
		}
		// regarding the code RequestSmimeBulkCertificates returns: TransactionID: cert.ID, Certificate: cert.Certificate, Pkcs7: cert.Pkcs7
		fmt.Print(transaction.Certificate)
	},
}

func init() {
	genCertCmd.AddCommand(genCertSmimeCmd)
	genCertSmimeCmd.Flags().String("csr", "", "CSR to request certificate with")
	genCertSmimeCmd.Flags().String("requester-email", "", "Email of requester")
	genCertSmimeCmd.Flags().String("requester-password", "", "Password of requester")
	genCertSmimeCmd.Flags().String("requester-totp-seed", "", "TOTP seed of requester")
	genCertSmimeCmd.Flags().String("validator-email", "", "Email of validator")
	genCertSmimeCmd.Flags().String("validator-password", "", "Password of validator")
	genCertSmimeCmd.Flags().String("validator-totp-seed", "", "TOTP seed of validator")
	genCertSmimeCmd.Flags().StringVar(&configPathSmime, "config", "", "config file (default is cert-generator.yaml)")
	// SMIME
	genCertSmimeCmd.Flags().StringP("cert-type", "t", "email_only", "Requested certificate cert type.")
	genCertSmimeCmd.Flags().String("email", "", "E-Mail Address for the desired certificate")
	genCertSmimeCmd.Flags().String("friendly-name", "", "Name to identify the certificate")
	genCertSmimeCmd.Flags().String("given-name", "", "Givenname of the certificate requestor")
	genCertSmimeCmd.Flags().String("sur-name", "", "Surname of the certificate requestor")
	for k, v := range keyMappingSmime {
		err := viper.BindPFlag(v, genCertSmimeCmd.Flags().Lookup(k))
		if err != nil {
			slog.Error("Failed to bind flag", slog.Any("error", err))
			os.Exit(1)
		}
	}

	for _, s := range []string{"requester-email", "requester-password", "validator-email", "validator-password", "validator-totp-seed"} {
		err := genCertSmimeCmd.MarkFlagRequired(s)
		if err != nil {
			slog.Error("Failed to mark flag required", slog.Any("error", err))
			os.Exit(1)
		}
	}
}
