package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type PCAPConfig struct {
	SnapshotLen int  `yaml:"snapshot_len"`
	Promiscuous bool `yaml:"promiscuous"`
	TimeoutMs   int  `yaml:"timeout_ms"`
}

type GeoIPConfig struct {
	CityDBPath string `yaml:"city_db_path"` // path to GeoLite2-City.mmdb
	ASNDBPath  string `yaml:"asn_db_path"`  // path to GeoLite2-ASN.mmdb (optional)
}

// IOCSourceConfig describes one blocklist file to load at startup.
// Type must be "ip", "domain", or "hash".
// Severity must be "low", "medium", "high", or "critical".
type IOCSourceConfig struct {
	Path     string `yaml:"path"`
	Source   string `yaml:"source"`   // e.g. "feodo-tracker", "abuse.ch", "custom"
	Type     string `yaml:"type"`     // "ip" | "domain" | "hash"
	Severity string `yaml:"severity"` // "low" | "medium" | "high" | "critical"
}

type IOCConfig struct {
	Sources []IOCSourceConfig `yaml:"sources"`
}

type Config struct {
	OutputDir      string      `yaml:"output_dir"`
	LogLevel       string      `yaml:"log_level"`
	ToolServerPort int         `yaml:"tool_server_port"`
	PCAP           PCAPConfig  `yaml:"pcap"`
	GeoIP          GeoIPConfig `yaml:"geoip"`
	IOC            IOCConfig   `yaml:"ioc"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}

	applyEnvOverrides(&cfg)
	return &cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("OUTPUT_DIR"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("TOOL_SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.ToolServerPort = port
		}
	}
	if v := os.Getenv("MAXMIND_DB_PATH"); v != "" {
		cfg.GeoIP.CityDBPath = v
	}
	if v := os.Getenv("MAXMIND_ASN_DB_PATH"); v != "" {
		cfg.GeoIP.ASNDBPath = v
	}
}
