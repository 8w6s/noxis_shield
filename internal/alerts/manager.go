package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/8w6s/noxis/config"
)

// AlertManager handles asynchronous Discord webhook notifications
type AlertManager struct {
	cfg      *config.AppConfig
	mu       sync.Mutex
	lastSent map[string]time.Time
}

// NewManager creates a new Alert properties and rate limits
func NewManager(cfg *config.AppConfig) *AlertManager {
	return &AlertManager{
		cfg:      cfg,
		lastSent: make(map[string]time.Time),
	}
}

// canSend checks rate limit for an alert type to avoid Discord API 429
func (a *AlertManager) canSend(alertType string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	cd := 5 * time.Minute // Default 5 minute ratelimit for global events
	if alertType == "ban_ip" {
		cd = 5 * time.Second // Faster ratelimit for individual bans
	}

	if last, ok := a.lastSent[alertType]; ok {
		if time.Since(last) < cd {
			return false
		}
	}
	a.lastSent[alertType] = time.Now()
	return true
}

// SendAttackStart sends the red DANGER alert when anomalies spike
func (a *AlertManager) SendAttackStart(rps float64, threshold float64) {
	if !a.canSend("attack_status") {
		return
	}

	embed := DiscordEmbed{
		Title:       "🚨 L7 DDoS ATTACK DETECTED",
		Description: "Noxis Anomaly Detector was triggered by abnormal traffic rates.",
		Color:       0xFF2442, // Red
		Fields: []DiscordField{
			{Name: "📊 Current RPS", Value: fmt.Sprintf("`%.2f req/s`", rps), Inline: true},
			{Name: "⚡ Threshold", Value: fmt.Sprintf("`%.2f req/s`", threshold), Inline: true},
			{Name: "🛡️ Action", Value: "Engaging JS Proof of Work / Blocklists", Inline: false},
		},
		Footer: DiscordFooter{Text: "Noxis Shield Engine"},
	}

	a.sendDiscord(embed)
}

// SendAttackEnd sends the green STABLE alert when traffic drops below threshold
func (a *AlertManager) SendAttackEnd(duration time.Duration) {
	if !a.canSend("attack_status") {
		// Even if we skip, we should reset the block so the next attack triggers.
		a.mu.Lock()
		delete(a.lastSent, "attack_status")
		a.mu.Unlock()
		return
	}

	embed := DiscordEmbed{
		Title:       "✅ TRAFFIC STABILIZED",
		Description: "The Layer 7 flood has subsided.",
		Color:       0x00E676, // Green
		Fields: []DiscordField{
			{Name: "⏱️ Attack Duration", Value: fmt.Sprintf("`%s`", duration.Round(time.Second).String()), Inline: true},
			{Name: "🍀 Status", Value: "System returning to nominal operation.", Inline: false},
		},
		Footer: DiscordFooter{Text: "Noxis Shield Engine"},
	}

	a.sendDiscord(embed)
}

// SendBan sends IP ban notification (Yellow)
func (a *AlertManager) SendBan(ip string, reason string) {
	if !a.canSend("ban_ip") {
		return
	}

	embed := DiscordEmbed{
		Title: "🔨 IP BLACKLISTED",
		Color: 0xFFAB00, // Amber
		Fields: []DiscordField{
			{Name: "🔴 IP Address", Value: fmt.Sprintf("`%s`", ip), Inline: true},
			{Name: "📝 Reason", Value: reason, Inline: true},
		},
		Footer: DiscordFooter{Text: "Noxis Shield Engine"},
	}

	a.sendDiscord(embed)
}

// SendEvent sends a generic system event notification (Blue)
func (a *AlertManager) SendEvent(title string, detail string) {
	if !a.canSend("system_event") {
		return
	}

	embed := DiscordEmbed{
		Title:       "ℹ️ SYSTEM EVENT: " + title,
		Description: detail,
		Color:       0x00B0FF, // Light Blue
		Footer:      DiscordFooter{Text: "Noxis Shield Engine"},
	}

	a.sendDiscord(embed)
}

// ================================================
// Discord JSON Binding Types
// ================================================

type DiscordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []DiscordField `json:"fields,omitempty"`
	Footer      DiscordFooter  `json:"footer,omitempty"`
}

type DiscordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type DiscordFooter struct {
	Text string `json:"text"`
}

// ================================================
// Dispatch Method
// ================================================

func (a *AlertManager) sendDiscord(embed DiscordEmbed) {
	if !a.cfg.Alerts.Discord.Enabled || a.cfg.Alerts.Discord.WebhookURL == "" {
		return
	}

	webhookUrl := a.cfg.Alerts.Discord.WebhookURL

	// Fire explicitly in background
	go func() {
		payload := map[string]interface{}{
			"embeds": []DiscordEmbed{embed},
		}
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("[Alerts] Failed to serialize discord payload: %v", err)
			return
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(webhookUrl, "application/json", bytes.NewReader(body))

		if err != nil {
			log.Printf("[Alerts] Failed to dispatch Discord webhook: %v", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			log.Printf("[Alerts] Discord returned non-200 code: %d", resp.StatusCode)
		} else {
			log.Printf("[Alerts] Sent Discord notification successfully.")
		}
	}()
}
