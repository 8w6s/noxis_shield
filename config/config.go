package config

import (
	"strings"

	"github.com/spf13/viper"
)

// AppConfig holds the complete configuration for Noxis
type AppConfig struct {
	Server    ServerConfig    `mapstructure:"server"`
	Shield    ShieldConfig    `mapstructure:"shield"`
	Redis     RedisConfig     `mapstructure:"redis"`
	RateLimit RateLimitConfig `mapstructure:"ratelimit"`
	Blocklist BlocklistConfig `mapstructure:"blocklist"`
	Anomaly   AnomalyConfig   `mapstructure:"anomaly"`
	Ebpf      EbpfConfig      `mapstructure:"ebpf"`
	Log       LogConfig       `mapstructure:"log"`
}

type ShieldConfig struct {
	Mode string `mapstructure:"mode"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type ServerConfig struct {
	Listen        string `mapstructure:"listen"`
	Upstream      string `mapstructure:"upstream"`
	DashboardPort string `mapstructure:"dashboard_port"`
	MetricsPort   string `mapstructure:"metrics_port"`
	AdminPort     string `mapstructure:"admin_port"`
}

type RateLimitConfig struct {
	WindowSeconds   int  `mapstructure:"window_seconds"`
	MaxRequests     int  `mapstructure:"max_requests"`
	SubnetThreshold int  `mapstructure:"subnet_threshold"`
	Adaptive        bool `mapstructure:"adaptive"`
}

type BlocklistConfig struct {
	TTLHours           int    `mapstructure:"ttl_hours"`
	AbuseIPDBKey       string `mapstructure:"abuseipdb_key"`
	AbuseIPDBThreshold int    `mapstructure:"abuseipdb_threshold"`
}

type AnomalyConfig struct {
	BaselineWindowMinutes int     `mapstructure:"baseline_window_minutes"`
	ZScoreThreshold       float64 `mapstructure:"zscore_threshold"`
	MaxConnectionsPerIP   int     `mapstructure:"max_connections_per_ip"`
}

type EbpfConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Interface    string `mapstructure:"interface"`
	SynRateLimit int    `mapstructure:"syn_rate_limit"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (*AppConfig, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	// Allow overriding via environment variables (e.g., NOXIS_SERVER_LISTEN)
	viper.SetEnvPrefix("NOXIS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config AppConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
