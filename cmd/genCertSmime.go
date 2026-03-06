package cmd

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
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
	Email          string `mapstructure:"email"`
	FriendlyName   string `mapstructure:"friendly_name"`
	GivenName      string `mapstructure:"given_name"`
	SurName        string `mapstructure:"sur_name"`
	PickupPassword string `mapstructure:"pickup_password"`
}

var (
	genCertSmimeConfig GenCertSmimeConfig
	configPathSmime    string
	smimeOutputType    string
	smimeOutputPath    string
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
		"pickup-password":     "pickup_password",
	}
)

// generateRandomPassword generates a random password in base64 format of the specified length
func generateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// resolvePickupPassword normalises the pickup password field on genCertSmimeConfig:
// - clears it when a CSR is provided (the server does not use it and may reject a non-empty value)
// - generates a random 16-char password when none was supplied
// - keeps the provided value otherwise
func resolvePickupPassword(cfg *GenCertSmimeConfig) error {
	if strings.TrimSpace(cfg.Csr) != "" {
		if cfg.PickupPassword != "" {
			slog.Info("Pickup password is ignored when a CSR is provided")
		}
		cfg.PickupPassword = ""
		return nil
	}
	if cfg.PickupPassword == "" {
		pw, err := generateRandomPassword(16)
		if err != nil {
			return err
		}
		cfg.PickupPassword = pw
		slog.Info("Generated random pickup password", slog.String("password", cfg.PickupPassword))
		return nil
	}
	slog.Info("Using provided pickup password", slog.String("password", cfg.PickupPassword))
	return nil
}

// resolvePKCSData returns the raw PKCS bytes and file extension to use for pkcs/zip
// output. It tries, in order: raw pkcsBytes from the API-key zip, base64-encoded
// pkcs12B64 from the session path, and finally pkcs7PEM from the session path.
func resolvePKCSData(pkcsBytes []byte, pkcsExt, pkcs12B64, pkcs7PEM string) ([]byte, string) {
	if len(pkcsBytes) > 0 {
		return pkcsBytes, pkcsExt
	}
	if pkcs12B64 != "" {
		data, err := base64.StdEncoding.DecodeString(pkcs12B64)
		if err != nil {
			slog.Error("failed to decode pkcs12 data", slog.Any("error", err))
			os.Exit(1)
		}
		return data, ".p12"
	}
	if pkcs7PEM != "" {
		return []byte(pkcs7PEM), ".p7b"
	}
	slog.Error("no PKCS data available for output")
	os.Exit(1)
	return nil, ""
}

// handleSmimeOutput runs the output switch shared by both the API-key and session
// paths. zipBytes and pkcsBytes/pkcsExt are only populated by the API-key path;
// certPEM, keyPEM, pkcs7PEM, and pkcs12B64 are used by both.
//
//   - pem:  prints certPEM (and keyPEM when present) to stdout
//   - pkcs: writes the resolved PKCS file to --output-path
//   - zip:  writes raw zipBytes to --output-path (API-key path), or builds a zip
//     from the resolved PKCS data (session path)
func handleSmimeOutput(certPEM, keyPEM, pkcs7PEM, pkcs12B64 string, pkcsBytes []byte, pkcsExt string, zipBytes []byte) {
	switch strings.ToLower(strings.TrimSpace(smimeOutputType)) {
	case "pem":
		fmt.Print(certPEM)
		if keyPEM != "" {
			fmt.Print(keyPEM)
		}
	case "pkcs":
		data, ext := resolvePKCSData(pkcsBytes, pkcsExt, pkcs12B64, pkcs7PEM)
		outPath := strings.TrimSpace(smimeOutputPath)
		if outPath == "" {
			outPath = filepath.Join(".", "smime"+ext)
		}
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			slog.Error("failed to write PKCS file", slog.String("path", outPath), slog.Any("error", err))
			os.Exit(1)
		}
		slog.Info("Wrote PKCS file", slog.String("path", outPath))
		fmt.Println(outPath)
	case "zip":
		outPath := strings.TrimSpace(smimeOutputPath)
		if outPath == "" {
			outPath = filepath.Join(".", "smime.zip")
		}
		if len(zipBytes) > 0 {
			if err := os.WriteFile(outPath, zipBytes, 0o644); err != nil {
				slog.Error("failed to write zip", slog.String("path", outPath), slog.Any("error", err))
				os.Exit(1)
			}
		} else {
			data, ext := resolvePKCSData(pkcsBytes, pkcsExt, pkcs12B64, pkcs7PEM)
			buf := new(bytes.Buffer)
			zw := zip.NewWriter(buf)
			f, err := zw.Create("smime" + ext)
			if err != nil {
				slog.Error("failed to create zip entry", slog.Any("error", err))
				os.Exit(1)
			}
			if _, err := f.Write(data); err != nil {
				slog.Error("failed to write zip entry", slog.Any("error", err))
				os.Exit(1)
			}
			if err := zw.Close(); err != nil {
				slog.Error("failed to finalise zip", slog.Any("error", err))
				os.Exit(1)
			}
			if err := os.WriteFile(outPath, buf.Bytes(), 0o644); err != nil {
				slog.Error("failed to write zip", slog.String("path", outPath), slog.Any("error", err))
				os.Exit(1)
			}
		}
		slog.Info("Wrote S/MIME ZIP", slog.String("path", outPath))
		fmt.Println(outPath)
	default:
		slog.Error("invalid output type; use pem, pkcs, or zip", slog.String("output-type", smimeOutputType))
		os.Exit(1)
	}
}

// buildSmimeBulkRequest constructs a SmimeBulkRequest from the resolved config.
func buildSmimeBulkRequest(cfg GenCertSmimeConfig) models.SmimeBulkRequest {
	return models.SmimeBulkRequest{
		FriendlyName:   cfg.FriendlyName,
		Email:          cfg.Email,
		Email2:         "",
		Email3:         "",
		GivenName:      cfg.GivenName,
		Surname:        cfg.SurName,
		PickupPassword: cfg.PickupPassword,
		CertType:       cfg.CertType,
		CSR:            cfg.Csr,
	}
}

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
				enterprises, raw, err := client.ListCMv1Enterprises(client.BaseURL(environment), resolvedAPIKey, debug)
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

			if err := resolvePickupPassword(&genCertSmimeConfig); err != nil {
				slog.Error("failed to resolve pickup password", slog.Any("error", err))
				os.Exit(1)
			}

			smimeBulk := buildSmimeBulkRequest(genCertSmimeConfig)
			slog.Debug("CSR logged:", slog.Any("csr", smimeBulk.CSR))

			zipBytes, err := client.CreateCMv1SmimeBulkZip(client.BaseURL(environment), resolvedAPIKey, resolvedOrganizationID, smimeBulk, debug)
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

			var certPEM, keyPEM string
			var pkcsBytes []byte
			var pkcsExt string
			switch strings.ToLower(strings.TrimSpace(smimeOutputType)) {
			case "pem":
				var err error
				certPEM, keyPEM, err = client.ExtractFirstCertificatePEMFromZip(zipBytes, genCertSmimeConfig.PickupPassword)
				if err != nil {
					slog.Error("failed to extract certificate from zip", slog.Any("error", err))
					os.Exit(1)
				}
			case "pkcs":
				var err error
				pkcsBytes, pkcsExt, err = client.ExtractPKCSFromZip(zipBytes)
				if err != nil {
					slog.Error("failed to extract PKCS file from zip", slog.Any("error", err))
					os.Exit(1)
				}
			}
			handleSmimeOutput(certPEM, keyPEM, "", "", pkcsBytes, pkcsExt, zipBytes)
			return
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

		if err := resolvePickupPassword(&genCertSmimeConfig); err != nil {
			slog.Error("failed to resolve pickup password", slog.Any("error", err))
			os.Exit(1)
		}

		// build fake bulk request with single user
		// it looks like the API still does not fully support requesting a single SMIME certificate
		// the request endpoint exists but no review/validation endpoint - atleast missing in API description
		smimeBulk := buildSmimeBulkRequest(genCertSmimeConfig)
		slog.Debug("CSR logged:", slog.Any("csr", smimeBulk.CSR))
		transaction, err := requester.RequestSmimeBulkCertificates(orgs[0].ID, smimeBulk)
		if err != nil {
			slog.Error("failed to request certificate", slog.Any("error", err))
			os.Exit(1)
		}
		handleSmimeOutput(transaction.Certificate, "", transaction.Pkcs7, transaction.Pkcs12, nil, "", nil)
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
	genCertSmimeCmd.Flags().String("pickup-password", "", "Password for certificate pickup (if not provided, a random password will be generated)")
	genCertSmimeCmd.Flags().StringVar(&smimeOutputType, "output-type", "pem", "Output type: pem (default), pkcs (.p12/.p7b), or zip")
	genCertSmimeCmd.Flags().StringVar(&smimeOutputPath, "output-path", "", "Output file path for pkcs and zip output types (default: ./smime.<ext>)")
}
