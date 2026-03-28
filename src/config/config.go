package config

import (
	"github.com/BurntSushi/toml"
)

type Config struct {
	Server    ServerConfig    `toml:"server"`
	Database  DatabaseConfig  `toml:"database"`
	PKI       PKIConfig       `toml:"pki"`
	WebAuthn  WebAuthnConfig  `toml:"webauthn"`
	Dashboard DashboardConfig `toml:"dashboard"`
}

type ServerConfig struct {
	ListenAddr  string `toml:"listen_addr"`
	TLSCertPath string `toml:"tls_cert_path"`
	TLSKeyPath  string `toml:"tls_key_path"`
	LogLevel    string `toml:"log_level"`
}

type DatabaseConfig struct {
	Driver string `toml:"driver"`
	DSN    string `toml:"dsn"`
}

type PKIConfig struct {
	KeyStorageDir string       `toml:"key_storage_dir"`
	DN            DNConfig     `toml:"dn"`
	TTL           TTLConfig    `toml:"ttl"`
	Keys          KeysConfig   `toml:"keys"`
	Policy        PolicyConfig `toml:"policy"`
}

type DNConfig struct {
	Country      []string `toml:"country"`
	Organization []string `toml:"organization"`
	Locality     []string `toml:"locality"`
}

type TTLConfig struct {
	RootCA         string `toml:"root_ca"`
	IntermediateCA string `toml:"intermediate_ca"`
	ServerLeaf     string `toml:"server_leaf"`
	ClientLeaf     string `toml:"client_leaf"`
}

type KeysConfig struct {
	Algorithm string `toml:"algorithm"`
	CASize    int    `toml:"ca_size"`
	LeafSize  int    `toml:"leaf_size"`
}

type PolicyConfig struct {
	AllowedDomains []string `toml:"allowed_domains"`
	AllowedIPs     []string `toml:"allowed_ips"`
}

type WebAuthnConfig struct {
	RPDisplayName string `toml:"rp_display_name"`
	RPID          string `toml:"rp_id"`
	RPOrigin      string `toml:"rp_origin"`
}

type DashboardConfig struct {
	SessionSecret string `toml:"session_secret"`
}

// DefaultConfig creates a Config struct populated with sane defaults.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			ListenAddr:  ":8443",
			TLSCertPath: "./data/certs/ui-cert.pem",
			TLSKeyPath:  "./data/certs/ui-key.pem",
			LogLevel:    "info",
		},
		Database: DatabaseConfig{
			Driver: "sqlite3",
			DSN:    "./data/camanager.db",
		},
		PKI: PKIConfig{
			KeyStorageDir: "./data/keys",
			DN: DNConfig{
				Country:      []string{"US"},
				Organization: []string{"My Homelab"},
				Locality:     []string{"Server Rack"},
			},
			TTL: TTLConfig{
				RootCA:         "87600h",
				IntermediateCA: "43800h",
				ServerLeaf:     "8760h",
				ClientLeaf:     "8760h",
			},
			Keys: KeysConfig{
				Algorithm: "ECDSA",
				CASize:    384,
				LeafSize:  256,
			},
			Policy: PolicyConfig{
				AllowedDomains: []string{"homelab.local", "*.homelab.local"},
				AllowedIPs:     []string{"192.168.1.0/24", "10.0.0.0/8"},
			},
		},
	}
}

// Load reads the TOML file and overlays it onto the default configuration.
func Load(filepath string) (*Config, error) {
	// 1. Get the defaults
	cfg := DefaultConfig()

	// 2. Decode the TOML file OVER the defaults
	// Any value present in the file will overwrite the default.
	// Any value missing in the file will retain its default.
	if _, err := toml.DecodeFile(filepath, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
