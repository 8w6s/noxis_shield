package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/8w6s/noxis/config"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

// Manager handles the generation and verification of JS Proof-of-Work challenges
type Manager struct {
	cfg    *config.AppConfig
	secret []byte
}

// NewManager creates a new JS Challenge manager
func NewManager(cfg *config.AppConfig) *Manager {
	secret := []byte(cfg.Protection.Challenge.CookieSecret)
	if len(secret) == 0 {
		secret = make([]byte, 32)
		rand.Read(secret)
	}
	return &Manager{cfg: cfg, secret: secret}
}

// ServeChallenge writes the JS PoW HTML page to the response
func (m *Manager) ServeChallenge(ctx *fasthttp.RequestCtx) {
	// Generate unique random challenge string
	challengeBytes := make([]byte, 16)
	rand.Read(challengeBytes)
	challengeStr := hex.EncodeToString(challengeBytes)

	difficulty := m.cfg.Protection.Challenge.PowDifficulty
	if difficulty == 0 {
		difficulty = 5 // Default
	}

	html := fmt.Sprintf(powTemplate, challengeStr, difficulty, string(ctx.RequestURI()))

	ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
	ctx.Response.Header.Set("Cache-Control", "no-store, no-cache")
	ctx.SetStatusCode(http.StatusServiceUnavailable) // 503 HTTP Code
	ctx.SetBodyString(html)
}

// VerifyProof checks if the incoming request has a valid HMAC signed proof cookie
func (m *Manager) VerifyProof(ctx *fasthttp.RequestCtx) bool {
	cookie := ctx.Request.Header.Cookie("noxis_proof")
	if len(cookie) == 0 {
		return false
	}

	parts := strings.SplitN(string(cookie), "|", 2)
	if len(parts) != 2 {
		return false
	}

	payload := parts[0]
	sig := parts[1]

	// Verify HMAC Signature
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return false
	}

	// Verify Expiration & IP Match
	payloadParts := strings.SplitN(payload, "_", 2)
	if len(payloadParts) == 2 {
		cookieIP := payloadParts[0]
		clientIP := utils.GetClientIP(ctx)

		if cookieIP != clientIP {
			return false // IP hijacking attempt
		}

		ts, err := strconv.ParseInt(payloadParts[1], 10, 64)
		if err == nil {
			issued := time.Unix(ts, 0)
			ttl := time.Duration(m.cfg.Protection.Challenge.CookieTTL) * time.Second
			if time.Since(issued) > ttl {
				return false // Expired
			}
			return true // Valid!
		}
	}

	return false
}

// VerifyPoW POST submission from the JS Solver and issues Cookie
func (m *Manager) HandleVerification(ctx *fasthttp.RequestCtx) bool {
	if !ctx.IsPost() {
		return false
	}

	nonce := string(ctx.FormValue("nonce"))
	challenge := string(ctx.FormValue("challenge"))
	difficultyStr := string(ctx.FormValue("difficulty"))
	clientIP := utils.GetClientIP(ctx)

	if nonce == "" || challenge == "" {
		return false
	}

	// Calculate Hash: SHA256(challenge + nonce)
	data := challenge + nonce
	hash := sha256.Sum256([]byte(data))
	hashHex := hex.EncodeToString(hash[:])

	difficulty, _ := strconv.Atoi(difficultyStr)
	if difficulty == 0 {
		difficulty = m.cfg.Protection.Challenge.PowDifficulty
	}

	// Ensure prefix has N leading zeros
	prefix := strings.Repeat("0", difficulty)
	if !strings.HasPrefix(hashHex, prefix) {
		return false
	}

	// Success! Issue Signed Cookie
	payload := fmt.Sprintf("%s_%d", clientIP, time.Now().Unix())
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	cookie := fasthttp.Cookie{}
	cookie.SetKey("noxis_proof")
	cookie.SetValue(payload + "|" + sig)
	cookie.SetPath("/")
	cookie.SetMaxAge(m.cfg.Protection.Challenge.CookieTTL)
	cookie.SetHTTPOnly(true)
	cookie.SetSameSite(fasthttp.CookieSameSiteLaxMode)

	ctx.Response.Header.SetCookie(&cookie)

	// Fast HTTP 200 OK Response
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString("ok")

	return true
}

const powTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checking your browser - Noxis Shield</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0d1117; color: #c9d1d9; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .container { text-align: center; max-width: 500px; padding: 40px; background: #161b22; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
        .spinner { width: 40px; height: 40px; border: 4px solid rgba(88, 166, 255, 0.2); border-left-color: #58a6ff; border-radius: 50%%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }
        h1 { font-size: 20px; margin-bottom: 10px; color: #ffffff; }
        p { font-size: 14px; color: #8b949e; line-height: 1.5; }
        .footer { margin-top: 30px; font-size: 12px; color: #484f58; }
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>Verifying you are human. This may take a few seconds.</h1>
        <p>Noxis Shield needs to review the security of your connection before proceeding.</p>
        <div class="footer">DDoS protection by Noxis Shield</div>
    </div>
    
    <script>
        // Simple client-side SHA-256 implementation natively in WebCrypto API
        async function sha256(message) {
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        async function solvePoW() {
            const challenge = "%s";
            const difficulty = %d;
            const prefix = "0".repeat(difficulty);
            
            let nonce = Math.floor(Math.random() * 100000);
            
            while (true) {
                const hash = await sha256(challenge + nonce);
                if (hash.startsWith(prefix)) {
                    // Solved! Submit answer
                    const formData = new URLSearchParams();
                    formData.append("challenge", challenge);
                    formData.append("nonce", nonce.toString());
                    formData.append("difficulty", difficulty.toString());

                    const resp = await fetch(window.location.pathname, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        body: formData.toString()
                    });

                    if (resp.ok) {
                        // Reload generic URL to clear POST state
                        window.location.href = "%s";
                    } else {
                        setTimeout(solvePoW, 1000); // Retry
                    }
                    break;
                }
                nonce++;
                
                // Yield thread to prevent UI freezing
                if (nonce %% 500 === 0) {
                    await new Promise(resolve => setTimeout(resolve, 0));
                }
            }
        }
        
        // Start solving on page load
        window.onload = () => {
             setTimeout(solvePoW, 1000); // Small 1s delay for dramatic effect
        };
    </script>
</body>
</html>`
