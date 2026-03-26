package config

import (
	"log"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Policy PolicyConfig `toml:"policy"`
}

type CAConfig struct {
	Distinguishedname DNConfig `toml:"dn"`
	Algorithm         string   `toml:"algorithm"`
}

type DNConfig struct {
	CN string `toml:"cn"`
	O  string `toml:"o"`
	OU string `toml:"ou"`
	L  string `toml:"l"`
	ST string `toml:"st"`
	C  string `toml:"c"`
	E  string `toml:"e"`
}

type PolicyConfig struct {
	AllowedDomains []string          `toml:"allowed_domains"`
	DefaultSANs    DefaultSANsConfig `toml:"default_sans"`
}

type DefaultSANsConfig struct {
	DNS []string `toml:"dns"`
	IPs []string `toml:"ips"`
}

type ServerConfig struct {
	Address string `toml:"address"`
}

type DatabaseConfig struct {
	DatabasePath string `toml:"path"`
}

func GetConfig() Config {
	var config Config

	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	return config
}
