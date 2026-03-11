package config

import (
	"strings"

	"github.com/spf13/viper"
)

// AppConfig holds the complete configuration for Noxis
type AppConfig struct {
	Server     ServerConfig     `mapstructure:"server"`
	Shield     ShieldConfig     `mapstructure:"shield"`
	Protection ProtectionConfig `mapstructure:"protection"`
	Alerts     AlertConfig      `mapstructure:"alerts"`
	WAF        WAFConfig        `mapstructure:"waf"`
	Redis      RedisConfig      `mapstructure:"redis"`
	RateLimit  RateLimitConfig  `mapstructure:"ratelimit"`
	Blocklist  BlocklistConfig  `mapstructure:"blocklist"`
	Reputation ReputationConfig `mapstructure:"reputation"`
	Anomaly    AnomalyConfig    `mapstructure:"anomaly"`
	Signals    SignalsConfig    `mapstructure:"signals"`
	Cluster    ClusterConfig    `mapstructure:"cluster"`
	Ebpf       EbpfConfig       `mapstructure:"ebpf"`
	Log        LogConfig        `mapstructure:"log"`
	TLS        TLSConfig        `mapstructure:"tls"`
	CGNAT      CGNATConfig      `mapstructure:"cgnat"`
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
	Listen        string   `mapstructure:"listen"`
	Upstreams     []string `mapstructure:"upstreams"`
	DashboardPort string   `mapstructure:"dashboard_port"`
	MetricsPort   string   `mapstructure:"metrics_port"`
	AdminPort     string   `mapstructure:"admin_port"`
}

type ProtectionConfig struct {
	Challenge ChallengeConfig `mapstructure:"challenge"`
}

type ChallengeConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	PowDifficulty  int    `mapstructure:"pow_difficulty"`
	CookieTTL      int    `mapstructure:"cookie_ttl"`
	CookieSecret   string `mapstructure:"cookie_secret"`
	ScoreThreshold int    `mapstructure:"score_threshold"` // signal engine score at which challenge is served (default: 25)
}

type AlertConfig struct {
	Discord DiscordAlertConfig `mapstructure:"discord"`
}

type DiscordAlertConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	WebhookURL string `mapstructure:"webhook_url"`
}

type WAFConfig struct {
	Enabled       bool `mapstructure:"enabled"`
	ParanoiaLevel int  `mapstructure:"paranoia_level"`
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

type ReputationConfig struct {
	BlockThreshold float64 `mapstructure:"block_threshold"`
}

// SignalsConfig configures the unified signal engine thresholds.
type SignalsConfig struct {
	ChallengeThreshold int `mapstructure:"challenge_threshold"` // default: 25
	ElevatedThreshold  int `mapstructure:"elevated_threshold"`  // default: 50
	BlockThreshold     int `mapstructure:"block_threshold"`     // default: 80
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

// ClusterConfig controls optional multi-node signal sharing via Redis Pub/Sub.
// Disabled by default — set enabled: true to activate.
type ClusterConfig struct {
	Enabled        bool    `mapstructure:"enabled"`
	NodeID         string  `mapstructure:"node_id"`         // auto UUID if empty
	Channel        string  `mapstructure:"channel"`         // default: noxis:cluster:events
	ImportWeight   float64 `mapstructure:"import_weight"`   // weight scale for imported signals (default 0.7)
	PreApplyBlocks bool    `mapstructure:"pre_apply_blocks"` // auto-block IPs from remote nodes
	TrustLevel     string  `mapstructure:"trust_level"`     // weak | medium | strong
}

type LogConfig struct {
	Level         string `mapstructure:"level"`
	Format        string `mapstructure:"format"`
	AccessLogPath string `mapstructure:"access_log_path"`
}

type TLSConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Domains []string `mapstructure:"domains"`
	Email   string   `mapstructure:"email"`
}

type CGNATConfig struct {
	TrustedProxies      []string `mapstructure:"trusted_proxies"`
	ExtractHeaders      []string `mapstructure:"extract_headers"`
	FallbackFingerprint bool     `mapstructure:"fallback_fingerprint"`
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
