package cmd

import (
	"cmp"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/hm-edu/harica/client"
	axfr "github.com/hm-edu/harica/dns"
	"github.com/hm-edu/harica/imap"
	"github.com/hm-edu/harica/models"
	"github.com/spf13/cobra"
)

type ValidationConfig struct {
	imapHost     string
	imapPort     int
	imapUsername string
	imapPassword string
	username     string
	password     string
	totp         string
	email        string
	dnsConfig    string
	domains      []string
}

var (
	config ValidationConfig
)

var validationCmd = &cobra.Command{
	Use: "validation",
	Run: func(cmd *cobra.Command, args []string) {

		dnsProvider, err := axfr.NewDNSProvider(config.dnsConfig)
		if err != nil {
			slog.Error("Failed to create dns provider", slog.Any("error", err))
		}

		if len(config.domains) > 10 {
			slog.Warn("You are trying to validate more than 10 domains. This is not recommended. You should use smaller batches.")
		}

		haricaClient, err := client.NewClient(config.username, config.password, config.totp, client.WithDebug(debug))
		if err != nil {
			slog.Error("Failed to create client:", slog.Any("error", err))
			return
		}

		orgs, err := haricaClient.GetOrganizations()
		if err != nil {
			slog.Error("Failed to get organizations:", slog.Any("error", err))
			return
		}

		validationStart := time.Now()
		validationDomains := []string{}

		slices.SortFunc(orgs, func(i, j models.Organization) int {
			return cmp.Compare(i.Domain, j.Domain)
		})

		for _, org := range orgs {
			if slices.Contains(config.domains, org.Domain) || len(config.domains) == 0 {
				if d, err := time.Parse("2006-01-02T15:04:05", org.Validity); err == nil && d.After(time.Now().Add(30*24*time.Hour)) {
					slog.Warn("Domain is already validated", slog.String("domain", org.Domain))
					continue
				}
				slog.Info("Triggering validation for domain", slog.String("domain", org.Domain))
				err = haricaClient.TriggerValidation(org.OrganizationID, config.email)
				if err != nil {
					slog.Error("Failed to validate domain:", slog.Any("error", err))
					return
				}
				validationDomains = append(validationDomains, org.Domain)
			}
		}

		if len(validationDomains) == 0 {
			slog.Info("No domains to validate")
			return
		}

		for _, domain := range validationDomains {
			if !dnsProvider.Configured(domain) {
				slog.Error("Domain not configured in dns provider", slog.String("domain", domain))
				return
			}
		}

		slog.Info("Validation triggered for domains", slog.Any("domains", validationDomains))

		slog.Info("Waiting for validation codes")
		validationCodes, err := imap.FetchValidationCodes(config.imapHost, config.imapUsername, config.imapPassword, config.imapPort, validationStart, validationDomains)
		if err != nil {
			slog.Error("Failed to fetch validation codes:", slog.Any("error", err))
			return
		}

		wg := sync.WaitGroup{}

		for domain, code := range validationCodes {
			slog.Info("Got validation code", slog.String("domain", domain), slog.String("code", code.Code))
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := client.NewClient(config.username, config.password, config.totp, client.WithDebug(debug))
				if err != nil {
					slog.Error("Failed to validate domain:", slog.Any("error", err))
				}
				err = validate(domain, code, dnsProvider, c)
				if err != nil {
					slog.Error("Failed to validate domain:", slog.Any("error", err))
				}
			}()
		}
		wg.Wait()

	},
}

func validate(domain string, code imap.ValidationCode, dnsProvider *axfr.DNSProvider, client *client.Client) error {
	records, err := dnsProvider.LookupTxt(domain)
	if err != nil {
		slog.Error("Failed to lookup TXT records:", slog.Any("error", err))
		return err
	}
	for _, record := range records {
		if strings.Contains(record, "HARICA-") {
			rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", domain, record))
			if err != nil {
				slog.Error("Failed to parse TXT record:", slog.Any("error", err))
				break
			}
			err = dnsProvider.Delete(domain, []dns.RR{rr})
			if err != nil {
				return err
			}
		}
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", domain, code.Code))
	if err != nil {
		slog.Error("Failed to create TXT record:", slog.Any("error", err))
		return err
	}
	err = dnsProvider.Add(domain, []dns.RR{rr})
	if err != nil {
		slog.Error("Failed to add TXT record:", slog.Any("error", err))
		return err
	}
	slog.Info("TXT record added. Waiting for validation. This step may take several minutes. (Timeout 5m)", slog.String("domain", domain), slog.String("code", code.Code))
	start := time.Now()
	for {
		valid := false
		orgsTmp, err := client.GetOrganizations()
		if err != nil {
			slog.Error("Failed to get organizations:", slog.Any("error", err))
			return err
		}
		for _, org := range orgsTmp {
			if org.Domain == domain {
				if d, err := time.Parse("2006-01-02T15:04:05", org.Validity); err == nil && d.After(time.Now()) {
					slog.Info("Domain is validated. Removing TXT record again.", slog.String("domain", org.Domain))
					err = dnsProvider.Delete(domain, []dns.RR{rr})
					if err != nil {
						return err
					}
					valid = true
				}
			}
		}
		if !valid && time.Since(start).Seconds() < 300 {
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}
	return nil
}

func init() {
	validationCmd.Flags().StringVar(&config.imapHost, "imap-host", "imap.example.com", "IMAP server hostname")
	validationCmd.Flags().IntVar(&config.imapPort, "imap-port", 993, "IMAP server port")
	validationCmd.Flags().StringVar(&config.imapUsername, "imap-username", "", "IMAP server username")
	validationCmd.Flags().StringVar(&config.imapPassword, "imap-password", "", "IMAP server password")
	validationCmd.MarkFlagRequired("imap-username") //nolint:errcheck
	validationCmd.MarkFlagRequired("imap-password") //nolint:errcheck
	validationCmd.MarkFlagRequired("imap-host")     //nolint:errcheck

	validationCmd.Flags().StringVarP(&config.username, "username", "u", "", "Harica username")
	validationCmd.Flags().StringVarP(&config.password, "password", "p", "", "Harica password")
	validationCmd.Flags().StringVarP(&config.totp, "totp-seed", "t", "", "Harica TOTP seed")

	validationCmd.MarkFlagRequired("username")  //nolint:errcheck
	validationCmd.MarkFlagRequired("password")  //nolint:errcheck
	validationCmd.MarkFlagRequired("totp-seed") //nolint:errcheck

	validationCmd.Flags().StringSliceVar(&config.domains, "domains", []string{}, "Domains to validate")
	validationCmd.Flags().StringVar(&config.email, "email", "", "Email to send validation code to")
	validationCmd.MarkFlagRequired("email") //nolint:errcheck

	validationCmd.Flags().StringVar(&config.dnsConfig, "dns", "", "Path to dns config")
	validationCmd.MarkFlagRequired("dns") //nolint:errcheck

	rootCmd.AddCommand(validationCmd)

}
