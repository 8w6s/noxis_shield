package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"mango-waf/cluster"
	"mango-waf/config"
	"mango-waf/logger"
)

// AlertManager handles multi-channel alerts with rate limiting
type AlertManager struct {
	cfg      *config.Config
	mu       sync.Mutex
	lastSent map[string]time.Time // rate limit per alert type
	cooldown time.Duration
}

// NewAlertManager creates a new alert manager
func NewAlertManager(cfg *config.Config) *AlertManager {
	return &AlertManager{
		cfg:      cfg,
		lastSent: make(map[string]time.Time),
		cooldown: 5 * time.Minute, // Tăng cooldown mặc định lên 5 phút để chống spam
	}
}

// RemoteSilence is called when another node in the mesh has already sent an alert
func (a *AlertManager) RemoteSilence(alertType string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSent[alertType] = time.Now()
	logger.Info("Alert silenced by Mesh sync", "type", alertType)
}

// canSend checks rate limit for an alert type
func (a *AlertManager) canSend(alertType string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Rate limit: 5 phút cho các cảnh báo tấn công, 30s cho các loại khác
	cd := a.cooldown
	if strings.Contains(alertType, "ban_") {
		cd = 30 * time.Second
	}

	if last, ok := a.lastSent[alertType]; ok {
		if time.Since(last) < cd {
			return false
		}
	}
	a.lastSent[alertType] = time.Now()

	// Phát tín hiệu ra Mesh để các máy khác im lặng
	if m := cluster.GetMesh(); m != nil {
		go m.BroadcastAlert(alertType)
	}

	return true
}

// SendAttackStart sends beautiful attack start notification
func (a *AlertManager) SendAttackStart(rps int64) {
	if !a.canSend("attack_start") {
		return
	}

	domains := make([]string, len(a.cfg.Domains))
	for i, d := range a.cfg.Domains {
		domains[i] = d.Name
	}

	// Telegram HTML format - Apex style
	clusterSize := 1
	if m := cluster.GetMesh(); m != nil {
		clusterSize = m.NumMembers()
	}

	telegramHTML := fmt.Sprintf(
		"🚨 <b>CẢNH BÁO TẤN CÔNG DDoS</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"🖥 <b>Node:</b> <code>%s</code>\n"+
			"🌐 <b>Domain:</b> %s\n"+
			"📊 <b>Lưu lượng:</b> <code>%d req/s</code>\n"+
			"⚡ <b>Ngưỡng:</b> <code>%d req/s</code> (x%.1f)\n"+
			"🔗 <b>Mesh Cluster:</b> <code>%d Nodes Online</code>\n\n"+
			"🔴 <b>Trạng thái:</b> <b>UNDER ATTACK</b>\n"+
			"🛡️ <b>Hành động:</b> Tự động nâng cấp bảo vệ\n\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield v2.2 — Apex Edition</i>",
		a.cfg.Cluster.NodeName,
		strings.Join(domains, ", "),
		rps,
		a.cfg.Protection.Emergency.RPSThreshold,
		float64(rps)/float64(a.cfg.Protection.Emergency.RPSThreshold),
		clusterSize,
	)

	// Discord embed
	discordEmbed := DiscordEmbed{
		Title:       "🚨 CẢNH BÁO TẤN CÔNG DDoS",
		Description: fmt.Sprintf("Phát hiện lưu lượng bất thường trên cluster **%s**", a.cfg.Cluster.NodeName),
		Color:       0xFF4B4B, // Red
		Fields: []DiscordField{
			{Name: "🖥 Node", Value: fmt.Sprintf("`%s`", a.cfg.Cluster.NodeName), Inline: true},
			{Name: "📊 RPS", Value: fmt.Sprintf("`%d req/s`", rps), Inline: true},
			{Name: "⚡ Ngưỡng", Value: fmt.Sprintf("`%d req/s`", a.cfg.Protection.Emergency.RPSThreshold), Inline: true},
			{Name: "🌐 Domains", Value: strings.Join(domains, ", "), Inline: false},
			{Name: "🔗 Cluster Status", Value: fmt.Sprintf("`%d Nodes Online`", clusterSize), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v2.2 Apex"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendAttackEnd sends attack ended notification
func (a *AlertManager) SendAttackEnd(duration time.Duration, blocked int64) {
	if !a.canSend("attack_end") {
		return
	}

	durStr := formatDuration(duration)

	telegramHTML := fmt.Sprintf(
		"✅ <b>TẤN CÔNG ĐÃ KẾT THÚC</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"🖥 <b>Node:</b> <code>%s</code>\n"+
			"⏱️ <b>Kéo dài:</b> <code>%s</code>\n"+
			"🔒 <b>Đã chặn:</b> <code>%s requests</code>\n\n"+
			"🍀 <b>Trạng thái:</b> <b>STABLE</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield v2.2 — Apex Edition</i>",
		a.cfg.Cluster.NodeName, durStr, formatNumber(blocked),
	)

	discordEmbed := DiscordEmbed{
		Title:       "✅ Tấn công đã kết thúc",
		Description: fmt.Sprintf("Đã phòng thủ thành công trên node **%s**", a.cfg.Cluster.NodeName),
		Color:       0x00D68F, // Green
		Fields: []DiscordField{
			{Name: "🖥 Node", Value: fmt.Sprintf("`%s`", a.cfg.Cluster.NodeName), Inline: true},
			{Name: "⏱️ Thời gian", Value: durStr, Inline: true},
			{Name: "🔒 Đã chặn", Value: formatNumber(blocked), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v2.2 Apex"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendBan sends IP ban notification
func (a *AlertManager) SendBan(ip, reason string, duration time.Duration) {
	if !a.canSend("ban_" + ip) {
		return
	}

	telegramHTML := fmt.Sprintf(
		"🔨 <b>IP ĐÃ BỊ CẤM (BAN)</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"� <b>Node:</b> <code>%s</code>\n"+
			"�🔴 <b>IP:</b> <code>%s</code>\n"+
			"📝 <b>Lý do:</b> <code>%s</code>\n"+
			"⏱️ <b>Thời hạn:</b> <code>%s</code>\n\n"+
			"🥭 <i>Mango Shield Apex</i>",
		a.cfg.Cluster.NodeName, ip, reason, formatDuration(duration),
	)

	discordEmbed := DiscordEmbed{
		Title: "🔨 IP đã bị cấm",
		Color: 0xFFB800,
		Fields: []DiscordField{
			{Name: "🖥 Node", Value: fmt.Sprintf("`%s`", a.cfg.Cluster.NodeName), Inline: true},
			{Name: "🔴 IP", Value: fmt.Sprintf("`%s`", ip), Inline: true},
			{Name: "📝 Lý do", Value: reason, Inline: true},
			{Name: "⏱️ Thời hạn", Value: formatDuration(duration), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v2.2 Apex"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendReport sends periodic status report
func (a *AlertManager) SendReport(totalReqs, blocked, passed, bannedIPs, attacks int64, uptime time.Duration) {
	if !a.canSend("report") {
		return
	}

	blockRate := float64(0)
	if totalReqs > 0 {
		blockRate = float64(blocked) / float64(totalReqs) * 100
	}

	telegramHTML := fmt.Sprintf(
		"📊 <b>BÁO CÁO HỆ THỐNG</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n\n"+
			"� <b>Node:</b> <code>%s</code>\n"+
			"📈 <b>Requests:</b> <code>%s</code>\n"+
			"🔒 <b>Đã chặn:</b> <code>%s</code> (%.1f%%)\n"+
			"✅ <b>Cho qua:</b> <code>%s</code>\n"+
			"🚫 <b>IP bị cấm:</b> <code>%d IP</code>\n"+
			"⚔️ <b>Tấn công:</b> <code>%d lần</code>\n"+
			"⏱️ <b>Uptime:</b> <code>%s</code>\n\n"+
			"━━━━━━━━━━━━━━━━━━━━━\n"+
			"🥭 <i>Mango Shield v2.2 — Apex Edition</i>",
		a.cfg.Cluster.NodeName,
		formatNumber(totalReqs), formatNumber(blocked), blockRate,
		formatNumber(passed), bannedIPs, attacks, formatDuration(uptime),
	)

	discordEmbed := DiscordEmbed{
		Title: "📊 Báo cáo định kỳ",
		Color: 0x6B7AFF,
		Fields: []DiscordField{
			{Name: "� Node", Value: fmt.Sprintf("`%s`", a.cfg.Cluster.NodeName), Inline: true},
			{Name: "⏱️ Uptime", Value: formatDuration(uptime), Inline: true},
			{Name: "📈 Tổng Req", Value: formatNumber(totalReqs), Inline: true},
			{Name: "� Đã chặn", Value: fmt.Sprintf("%s (%.1f%%)", formatNumber(blocked), blockRate), Inline: true},
			{Name: "🚫 IP cấm", Value: fmt.Sprintf("%d", bannedIPs), Inline: true},
			{Name: "⚔️ Tấn công", Value: fmt.Sprintf("%d", attacks), Inline: true},
		},
		Footer: DiscordFooter{Text: "🥭 Mango Shield v2.2 Apex"},
	}

	a.sendAllRich(telegramHTML, discordEmbed)
}

// SendCustom sends a custom alert message
func (a *AlertManager) SendCustom(msg string) {
	telegramHTML := fmt.Sprintf("ℹ️ <b>Mango Shield</b>\n\n%s", msg)
	discordEmbed := DiscordEmbed{
		Title:       "ℹ️ Thông báo",
		Description: msg,
		Color:       0x6B7AFF,
		Footer:      DiscordFooter{Text: "🥭 Mango Shield v2.0"},
	}
	a.sendAllRich(telegramHTML, discordEmbed)
}

// ================================================
// Discord Embed types
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
// Send methods
// ================================================

func (a *AlertManager) sendAllRich(telegramHTML string, discordEmbed DiscordEmbed) {
	if a.cfg.Alerts.Telegram.Enabled {
		go a.sendTelegram(telegramHTML)
	}
	if a.cfg.Alerts.Discord.Enabled {
		go a.sendDiscord(discordEmbed)
	}
	if a.cfg.Alerts.Webhook.Enabled {
		go a.sendWebhook(telegramHTML)
	}
}

func (a *AlertManager) sendTelegram(html string) {
	cfg := a.cfg.Alerts.Telegram
	if cfg.Token == "" || cfg.ChatID == "" {
		return
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.Token)

	resp, err := http.PostForm(apiURL, url.Values{
		"chat_id":                  {cfg.ChatID},
		"text":                     {html},
		"parse_mode":               {"HTML"},
		"disable_web_page_preview": {"true"},
	})
	if err != nil {
		logger.Error("Telegram gửi thất bại", "error", err)
		return
	}
	resp.Body.Close()
}

func (a *AlertManager) sendDiscord(embed DiscordEmbed) {
	cfg := a.cfg.Alerts.Discord
	if cfg.WebhookURL == "" {
		return
	}

	payload := map[string]interface{}{
		"embeds": []DiscordEmbed{embed},
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(cfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		logger.Error("Discord gửi thất bại", "error", err)
		return
	}
	resp.Body.Close()
}

func (a *AlertManager) sendWebhook(text string) {
	cfg := a.cfg.Alerts.Webhook
	if cfg.URL == "" {
		return
	}

	payload := map[string]interface{}{
		"message":   text,
		"timestamp": time.Now().Format(time.RFC3339),
		"source":    "mango-shield",
		"version":   "2.0.0",
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Secret != "" {
		req.Header.Set("X-Webhook-Secret", cfg.Secret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("Webhook gửi thất bại", "error", err)
		return
	}
	resp.Body.Close()
}

// ================================================
// Helpers
// ================================================

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fB", float64(n)/1000000000)
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 24 {
		days := h / 24
		return fmt.Sprintf("%d ngày %d giờ", days, h%24)
	}
	if h > 0 {
		return fmt.Sprintf("%d giờ %d phút", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%d phút %d giây", m, s)
	}
	return fmt.Sprintf("%d giây", s)
}
