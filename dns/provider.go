package dns

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type DNSProvider struct {
	Configs []ProviderConfig
}

const (
	// maximum time DNS client can be off from server for an update to succeed
	clockSkew = 300

	// maximum size of a UDP transport message in DNS protocol
	udpMaxMsgSize = 512
)

func (d *DNSProvider) LookupTxt(domain string) ([]string, error) {
	server := "8.8.8.8"
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	r, _, err := c.Exchange(&m, server+":53")
	if err != nil {
		return nil, err
	}
	if len(r.Answer) == 0 {
		return []string{}, nil
	}

	var txts []string

	for _, ans := range r.Answer {
		switch v := ans.(type) {
		case *dns.TXT:
			txts = append(txts, strings.Join(v.Txt, ""))
		}
	}
	return txts, nil
}

func NewDNSProvider(config string) (*DNSProvider, error) {
	data, err := os.ReadFile(config)
	if err != nil {
		fmt.Println("Error reading config file: ", err)
		return nil, err
	}

	providerConfigs := Provider{}
	err = yaml.Unmarshal(data, &providerConfigs)

	if err != nil {
		fmt.Println("Error unmarshalling config file: ", err)
		return nil, err
	}

	return &DNSProvider{
		Configs: providerConfigs.Zones,
	}, nil
}

func (r *DNSProvider) Configured(domain string) bool {
	_, err := r.matchingProvider(domain)
	return err == nil
}

// Add adds the given records to the zone.
func (r *DNSProvider) Add(domain string, entries []dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(domain))
	m.Insert(entries)
	return r.sendMessage(domain, m)

}

// Delete removes the given records from the zone.
func (r *DNSProvider) Delete(domain string, entries []dns.RR) error {
	m := new(dns.Msg)
	m.SetUpdate(dns.Fqdn(domain))
	m.Remove(entries)
	return r.sendMessage(domain, m)
}

func (r *DNSProvider) matchingProvider(domain string) (*ProviderConfig, error) {

	var matchingConfig *ProviderConfig
	matchingConfig = nil
	for _, config := range r.Configs {

		if config.BaseDomain == "" {
			matchingConfig = &config
			continue
		}

		if strings.HasSuffix(dns.Fqdn(domain), fmt.Sprintf(".%s", dns.Fqdn(config.BaseDomain))) || dns.Fqdn(domain) == dns.Fqdn(config.BaseDomain) {
			if matchingConfig == nil {
				matchingConfig = &config
				continue
			}

			if len(strings.Split(config.BaseDomain, ".")) > len(strings.Split(matchingConfig.BaseDomain, ".")) {
				matchingConfig = &config
			}
		}
	}

	if matchingConfig == nil {
		return nil, fmt.Errorf("no matching DNS provider found for domain %s", domain)
	}
	return matchingConfig, nil
}

func (r *DNSProvider) sendMessage(domain string, msg *dns.Msg) error {

	c := new(dns.Client)

	cfg, err := r.matchingProvider(domain)
	if err != nil {
		return err
	}
	c.TsigSecret = map[string]string{cfg.TsigKeyName: cfg.TsigSecret}
	msg.SetTsig(cfg.TsigKeyName, cfg.TsigSecretAlg, clockSkew, time.Now().Unix())
	if cfg.TsigSecretAlg == dns.HmacMD5 {
		c.TsigProvider = Md5provider(cfg.TsigSecret)
	}
	if msg.Len() > udpMaxMsgSize || cfg.Net == "tcp" {
		c.Net = "tcp"
	}
	resp, _, err := c.Exchange(msg, cfg.Nameserver)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("no response received")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("bad return code: %s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}
