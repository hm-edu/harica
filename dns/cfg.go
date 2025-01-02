package dns

type Provider struct {
	Zones []ProviderConfig `yaml:"zones"`
}

type ProviderConfig struct {
	BaseDomain    string `yaml:"domain"`
	Nameserver    string `yaml:"nameserver"`
	TsigKeyName   string `yaml:"tsig_key_name"`
	TsigSecret    string `yaml:"tsig_secret"`
	TsigSecretAlg string `yaml:"tsig_secret_alg"`
	Net           string `yaml:"net"`
}
