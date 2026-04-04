package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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

type ThreatIntelConfig struct {
	CacheTTLMinutes int `yaml:"cache_ttl_minutes"`
	HTTPTimeoutSec  int `yaml:"http_timeout_sec"`
}

type PostgresConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"ssl_mode"`
}

type RedisConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type SentryConfig struct {
	DSN         string `yaml:"dsn"`
	Environment string `yaml:"environment"`
	Release     string `yaml:"release"`
	Enabled     bool   `yaml:"enabled"`
}

type CORSConfig struct {
	AllowedOrigins []string `yaml:"allowed_origins"` // e.g. ["*"] or ["http://localhost:3000"]
}

type Config struct {
	OutputDir      string            `yaml:"output_dir"`
	LogLevel       string            `yaml:"log_level"`
	ToolServerPort int               `yaml:"tool_server_port"`
	PCAP           PCAPConfig        `yaml:"pcap"`
	GeoIP          GeoIPConfig       `yaml:"geoip"`
	IOC            IOCConfig         `yaml:"ioc"`
	ThreatIntel    ThreatIntelConfig `yaml:"threat_intel"`
	Postgres       PostgresConfig    `yaml:"postgres"`
	Redis          RedisConfig       `yaml:"redis"`
	Sentry         SentryConfig      `yaml:"sentry"`
	CORS           CORSConfig        `yaml:"cors"`
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
	if v := os.Getenv("DB_HOST"); v != "" {
		cfg.Postgres.Host = v
	}
	if v := os.Getenv("DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Postgres.Port = port
		}
	}
	if v := os.Getenv("DB_USER"); v != "" {
		cfg.Postgres.User = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" {
		cfg.Postgres.Password = v
	}
	if v := os.Getenv("DB_NAME"); v != "" {
		cfg.Postgres.DBName = v
	}
	if v := os.Getenv("DB_ENABLED"); v != "" {
		cfg.Postgres.Enabled = (v == "true" || v == "1")
	}
	if v := os.Getenv("REDIS_HOST"); v != "" {
		cfg.Redis.Host = v
	}
	if v := os.Getenv("REDIS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Redis.Port = port
		}
	}
	if v := os.Getenv("REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil {
			cfg.Redis.DB = db
		}
	}
	if v := os.Getenv("REDIS_ENABLED"); v != "" {
		cfg.Redis.Enabled = (v == "true" || v == "1")
	}
	if v := os.Getenv("SENTRY_DSN"); v != "" {
		cfg.Sentry.DSN = v
	}
	if v := os.Getenv("SENTRY_ENVIRONMENT"); v != "" {
		cfg.Sentry.Environment = v
	}
	if v := os.Getenv("SENTRY_RELEASE"); v != "" {
		cfg.Sentry.Release = v
	}
	if v := os.Getenv("SENTRY_ENABLED"); v != "" {
		cfg.Sentry.Enabled = (v == "true" || v == "1")
	}
	if v := os.Getenv("VIRUSTOTAL_API_KEY"); v != "" {
		// keys are used directly from env in enrichment/threatintel.go
	}
	if v := os.Getenv("CORS_ALLOWED_ORIGINS"); v != "" {
		// comma-separated: "http://localhost:3000,https://app.example.com" or "*"
		for _, origin := range strings.Split(v, ",") {
			if o := strings.TrimSpace(origin); o != "" {
				cfg.CORS.AllowedOrigins = append(cfg.CORS.AllowedOrigins, o)
			}
		}
	}
}
