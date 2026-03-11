package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func signValue(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// serveChallenge serves the appropriate challenge page
func (s *Shield) serveChallenge(w http.ResponseWriter, r *http.Request, action Action) {
	switch action.Stage {
	case 1:
		s.serveJSChallenge(w, r, action.Difficulty)
	case 2:
		s.serveCaptchaChallenge(w, r)
	}
}

// serveJSChallenge serves the JavaScript PoW challenge
func (s *Shield) serveJSChallenge(w http.ResponseWriter, r *http.Request, difficulty int) {
	nonce := randomHex(20)
	task := nonce + ":" + strconv.Itoa(difficulty)

	html := challengeHTML
	html = strings.ReplaceAll(html, "{{POW}}", task)
	html = strings.ReplaceAll(html, "{{DOMAIN}}", r.Host)

	// Sign the nonce for verification
	sig := signValue(nonce, s.cfg.Protection.Challenge.CookieSecret)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Mango-Shield", "challenge")
	http.SetCookie(w, &http.Cookie{
		Name:     "mango_pow",
		Value:    nonce + "." + sig,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(html))
}

// serveCaptchaChallenge serves a harder PoW challenge (stage 2 — internal only)
func (s *Shield) serveCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	// Stage 2 uses harder PoW (+2 difficulty) instead of external CAPTCHA
	s.serveJSChallenge(w, r, s.cfg.Protection.Challenge.PowDifficulty+2)
}

// init initializes challenge templates from built-in defaults
func init() {
	challengeHTML = defaultChallengeHTML
}

var (
	challengeHTML string
)

// --- Default Templates ---

var defaultChallengeHTML = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Check - Mango Shield</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:linear-gradient(135deg,#0a0a0a 0%%,#1a1a2e 50%%,#16213e 100%%);
  color:#fff;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;
}
.container{text-align:center;padding:40px;max-width:500px}
.shield{
  width:80px;height:80px;margin:0 auto 24px;
  background:linear-gradient(135deg,#ff6b35,#f7c948);
  border-radius:50%%;display:flex;align-items:center;justify-content:center;
  font-size:40px;animation:pulse 2s ease-in-out infinite;
  box-shadow:0 0 40px rgba(255,107,53,0.3);
}
@keyframes pulse{0%%,100%%{transform:scale(1);box-shadow:0 0 40px rgba(255,107,53,0.3)}
50%%{transform:scale(1.05);box-shadow:0 0 60px rgba(255,107,53,0.5)}}
h1{font-size:24px;margin-bottom:12px;font-weight:600}
p{color:#a0a0b0;margin-bottom:24px;line-height:1.6}
.progress{
  width:100%%;height:4px;background:#2a2a3e;border-radius:2px;overflow:hidden;
  margin:20px 0;
}
.progress-bar{
  width:0%%;height:100%%;background:linear-gradient(90deg,#ff6b35,#f7c948);
  border-radius:2px;transition:width 0.3s;animation:loading 3s ease-in-out forwards;
}
@keyframes loading{0%%{width:0%%}50%%{width:70%%}100%%{width:100%%}}
.footer{margin-top:30px;font-size:12px;color:#505060}
.spinner{display:inline-block;width:20px;height:20px;border:2px solid #333;
border-top-color:#ff6b35;border-radius:50%%;animation:spin 0.8s linear infinite;
vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
<div class="shield">🥭</div>
<h1>Verifying your browser...</h1>
<p>This is an automatic security check. Please wait while we verify your connection.</p>
<div class="progress"><div class="progress-bar"></div></div>
<p><span class="spinner"></span> Processing security challenge...</p>
<div class="footer">Protected by Mango Shield v2.0</div>
</div>
<script>
var t="{{POW}}".split(':');var n=t[0],d=parseInt(t[1])||1500000;var h=0;
for(var i=0;i<d;i++)h=((h<<5)-h+n.charCodeAt(i%%n.length))|0;
document.cookie="mango_proof="+h+"."+n+";path=/;max-age=3600;SameSite=Strict";
setTimeout(function(){location.reload()},500);
</script>
</body>
</html>`)
