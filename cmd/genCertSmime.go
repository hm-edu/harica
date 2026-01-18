package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	//SMIME
	Email        string `mapstructure:"email"`
	FriendlyName string `mapstructure:"friendly_name"`
	GivenName    string `mapstructure:"given_name"`
	SurName      string `mapstructure:"sur_name"`
}

var (
	genCertSmimeConfig GenCertSmimeConfig
	configPathSmime    string
	smimeOutputFormat  string
	smimeZipOutPath    string
	keyMappingSmime    = map[string]string{
		"csr":                 "csr",
		"cert-type":           "cert_type",
		"requester-email":     "requester_email",
		"requester-password":  "requester_password",
		"requester-totp-seed": "requester_totp_seed",
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

		for k, v := range keyMappingSmime {
			err := viper.BindPFlag(v, cmd.Flags().Lookup(k))
			if err != nil {
				slog.Error("Failed to bind flag", slog.Any("error", err))
				os.Exit(1)
			}
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
		resolvedAPIKey := viper.GetString("api_key")
		resolvedOrganizationID := viper.GetString("organization_id")

		// improve
		if len(genCertSmimeConfig.Email) == 0 {
			slog.Error("'emails' is required at the moment.")
			os.Exit(1)
		}

		genCertSmimeConfig.Csr = strings.ReplaceAll(genCertSmimeConfig.Csr, "\\n", "\n")

		if strings.TrimSpace(resolvedAPIKey) != "" {
			slog.Info("Using API-key mode for S/MIME bulk issuance")
			if strings.TrimSpace(resolvedOrganizationID) == "" {
				slog.Info("No organization id provided; attempting autodiscovery via /cm/v1/admin/enterprises")
				enterprises, raw, err := client.ListCMv1Enterprises(client.BaseURLProduction, resolvedAPIKey, debug)
				if err != nil {
					if len(raw) > 0 {
						fmt.Fprintln(os.Stderr, string(raw))
					}
					slog.Error("failed to autodiscover organization id", slog.Any("error", err))
					os.Exit(1)
				}
				unique := map[string]struct{}{}
				for _, e := range enterprises {
					id := strings.TrimSpace(e.OrganizationID)
					if id == "" {
						continue
					}
					unique[id] = struct{}{}
				}
				switch len(unique) {
				case 1:
					for id := range unique {
						resolvedOrganizationID = id
						break
					}
					slog.Info("Autodiscovered organization id", slog.String("organization_id", resolvedOrganizationID))
				case 0:
					slog.Error("no organization ids available for this api key; provide an organization-id or run 'harica --api-key ... org-ids'")
					os.Exit(1)
				default:
					slog.Error("multiple organization ids available; provide an organization-id or run 'harica --api-key ... org-ids' to list options")
					os.Exit(1)
				}
			}

			slog.Debug("Using organization id", slog.String("organization_id", resolvedOrganizationID))

			var smimeBulk = models.SmimeBulkRequest{
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
			if debug {
				slog.Debug("CSR logged:", slog.Any("csr", smimeBulk.CSR))
			}

			zipBytes, err := client.CreateCMv1SmimeBulkZip(client.BaseURLProduction, resolvedAPIKey, resolvedOrganizationID, smimeBulk, debug)
			if err != nil {
				if e, ok := err.(*client.UnexpectedResponseCodeError); ok {
					fmt.Fprintln(os.Stderr, string(e.Body))
					os.Exit(1)
				}
				if e, ok := err.(*client.UnexpectedResponseContentTypeError); ok {
					fmt.Fprintln(os.Stderr, string(e.Body))
					os.Exit(1)
				}
				slog.Error("failed to request certificate", slog.Any("error", err))
				os.Exit(1)
			}

			output := strings.ToLower(strings.TrimSpace(smimeOutputFormat))
			if output == "" {
				output = "pem"
			}
			switch output {
			case "zip":
				outPath := strings.TrimSpace(smimeZipOutPath)
				if outPath == "" {
					outPath = filepath.Join(".", "smime.zip")
				}
				if err := os.WriteFile(outPath, zipBytes, 0o644); err != nil {
					slog.Error("failed to write zip", slog.String("path", outPath), slog.Any("error", err))
					os.Exit(1)
				}
				slog.Info("Wrote S/MIME ZIP", slog.String("path", outPath))
				fmt.Println(outPath)
				return
			case "pem":
				pemCert, err := client.ExtractFirstCertificatePEMFromZip(zipBytes)
				if err != nil {
					slog.Error("failed to extract certificate from zip", slog.Any("error", err))
					os.Exit(1)
				}
				fmt.Print(pemCert)
				return
			default:
				slog.Error("invalid output format; use pem or zip", slog.String("output", smimeOutputFormat))
				os.Exit(1)
			}
		}

		if strings.TrimSpace(genCertSmimeConfig.RequesterEmail) == "" || strings.TrimSpace(genCertSmimeConfig.RequesterPassword) == "" || strings.TrimSpace(genCertSmimeConfig.RequesterTOTPSeed) == "" {
			slog.Error("requester credentials are required when no api key is provided (requester-email, requester-password, requester-totp-seed)")
			os.Exit(1)
		}

		requester, err := client.NewClient(genCertSmimeConfig.RequesterEmail, genCertSmimeConfig.RequesterPassword, genCertSmimeConfig.RequesterTOTPSeed, client.WithDebug(debug), client.WithEnvironment(environment))
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
		var smimeBulk = models.SmimeBulkRequest{
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
	genCertSmimeCmd.Flags().StringVar(&configPathSmime, "config", "", "config file (default is cert-generator.yaml)")
	// SMIME
	genCertSmimeCmd.Flags().StringP("cert-type", "t", "email_only", "Requested certificate cert type.")
	genCertSmimeCmd.Flags().String("email", "", "E-Mail Address for the desired certificate")
	genCertSmimeCmd.Flags().String("friendly-name", "", "Name to identify the certificate")
	genCertSmimeCmd.Flags().String("given-name", "", "Givenname of the certificate requestor")
	genCertSmimeCmd.Flags().String("sur-name", "", "Surname of the certificate requestor")
	genCertSmimeCmd.Flags().StringVar(&smimeOutputFormat, "output", "pem", "Output format in API-key mode: pem (default) or zip")
	genCertSmimeCmd.Flags().StringVar(&smimeZipOutPath, "zip-out", "", "Output ZIP path when --output=zip (default: ./smime.zip)")
}
