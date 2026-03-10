# NOXIS — Project Specification Document
> Tài liệu này mô tả toàn bộ dự án Noxis để AI IDE thực thi.
> Đọc kỹ từng phần trước khi bắt đầu viết code.

---

## 1. Tổng quan dự án

**Tên dự án:** Noxis
**Tagline:** L4/L7 DDoS Mitigation Engine — Traffic filtering from the shadows
**GitHub:** `github.com/8w6s/noxis`
**Ngôn ngữ backend:** Go 1.22
**Ngôn ngữ frontend:** TypeScript
**Frontend framework:** Vite + React + TypeScript

Noxis là một reverse proxy thông minh đứng trước ứng dụng của người dùng, lọc toàn bộ traffic độc hại trước khi nó đến được upstream app. Hệ thống hoạt động trên Linux VPS, sử dụng eBPF/XDP để lọc ở kernel-level (L3/L4) và Go userspace để xử lý L7.

---

## 2. Kiến trúc hệ thống

### 2.1 Flow tổng quát

```
Internet Traffic
       │
       ▼
┌──────────────────────────────────┐
│  LAYER 1: The Shield            │
│  (Platform Agnostic)            │
│  - Linux: eBPF/XDP (Kernel)     │
│  - Windows/Mac: Go Userspace    │
│  - Lọc SYN flood, UDP flood     │
│  - Drop packet độc hại nhanh    │
└────────────┬─────────────────────┘
             │ Clean packets only
             ▼
┌──────────────────────────────────┐
│  LAYER 2: Noxis Engine (Go)     │
│                                  │
│  Pipeline (theo thứ tự):        │
│  [1] Blocklist check            │
│  [2] Rate limiter               │
│  [3] Anomaly detector           │
│                                  │
│  Port 8080 — proxy traffic      │
│  Port 9090 — WebSocket/SSE      │
│  Port 2112 — Prometheus metrics │
└────────────┬─────────────────────┘
             │ Verified clean traffic
             ▼
┌──────────────────────────────────┐
│  Upstream App                   │
│  (chạy localhost, không expose) │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│  Dashboard (Vite + React + TS)  │
│  Static files, host qua Nginx   │
│  Kết nối WebSocket port 9090    │
└──────────────────────────────────┘
```

### 2.2 Deployment topology

```
VPS (Linux, Ubuntu 22.04+)
├── Noxis binary (port 8080, 9090, 2112)
├── Redis (localhost:6379) — rate limit state
├── Nginx — serve dashboard static files
└── Upstream app (localhost:3000) — app người dùng
```

DNS của domain người dùng trỏ vào VPS. Noxis nhận toàn bộ traffic, upstream app không bao giờ expose trực tiếp ra internet.

---

## 3. Cấu trúc thư mục

```
noxis/
├── cmd/
│   ├── noxis/
│   │   └── main.go                 # Entrypoint chính
│   └── noxctl/
│       └── main.go                 # CLI quản lý blocklist
├── internal/
│   ├── proxy/
│   │   ├── pipeline.go             # Middleware chain interface
│   │   └── server.go               # fasthttp reverse proxy server
│   ├── ratelimit/
│   │   └── limiter.go              # Sliding window rate limiter
│   ├── blocklist/
│   │   └── blocklist.go            # IP blocklist với TTL
│   ├── anomaly/
│   │   └── detector.go             # Z-score anomaly detection
│   ├── metrics/
│   │   └── prometheus.go           # Prometheus metrics exporter
│   ├── websocket/
│   │   └── hub.go                  # WebSocket hub push sang dashboard
│   └── ebpf/
│       └── loader.go               # Load eBPF program vào kernel
├── ebpf/
│   └── xdp_filter.c                # eBPF C program (kernel code)
├── config/
│   └── noxis.yaml                  # Config file
├── dashboard/                      # Vite + React + TS project
│   ├── src/
│   │   ├── components/
│   │   │   ├── MetricCard.tsx
│   │   │   ├── TrafficChart.tsx
│   │   │   ├── BlocklistTable.tsx
│   │   │   └── EventFeed.tsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts
│   │   │   └── useMetrics.ts
│   │   ├── types/
│   │   │   └── metrics.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── docker-compose.yml
├── go.mod
├── go.sum
└── README.md
```

---

## 4. Backend — Go

### 4.1 Dependencies (go.mod)

```
module github.com/8w6s/noxis

go 1.22

require (
    github.com/cilium/ebpf v0.15.0
    github.com/redis/go-redis/v9 v9.5.1
    github.com/valyala/fasthttp v1.55.0
    github.com/prometheus/client_golang v1.19.0
    github.com/charmbracelet/bubbletea v0.26.0
    github.com/charmbracelet/lipgloss v0.10.0
    github.com/gorilla/websocket v1.5.1
    github.com/spf13/viper v1.18.2
    go.uber.org/zap v1.27.0
)
```

### 4.2 Config file (config/noxis.yaml)

```yaml
server:
  listen: ":8080"            # Port nhận traffic từ internet
  upstream: "http://localhost:3000"  # App của người dùng
  dashboard_port: ":9090"    # WebSocket cho dashboard
  metrics_port: ":2112"      # Prometheus scrape endpoint

ratelimit:
  window_seconds: 10         # Sliding window size
  max_requests: 100          # Max request trong window
  subnet_threshold: 5        # Block /24 nếu >= 5 IPs cùng subnet attack
  adaptive: true             # Tự tăng limit cho IP clean lâu ngày

blocklist:
  ttl_hours: 24              # Auto-expire sau N giờ
  abuseipdb_key: ""          # API key AbuseIPDB (để trống nếu không dùng)
  abuseipdb_threshold: 50    # Score 0-100, block nếu trên ngưỡng này

anomaly:
  baseline_window_minutes: 60  # Học baseline trong 60 phút đầu
  zscore_threshold: 3.0        # Trigger alert khi vượt 3 standard deviations
  max_connections_per_ip: 20   # Slowloris detection

ebpf:
  enabled: true
  interface: "eth0"            # Network interface
  syn_rate_limit: 500          # Max SYN packets/s per IP

log:
  level: "info"               # debug | info | warn | error
  format: "json"
```

### 4.3 Module: proxy/pipeline.go

Pipeline là core của Noxis. Mỗi request đi qua các Handler theo thứ tự. Handler nào return `false` thì chain dừng lại, request bị block.

```go
// Handler interface — mỗi module implement interface này
type Handler interface {
    Process(ctx *fasthttp.RequestCtx) bool
    Name() string
}

// Pipeline chains handlers
type Pipeline struct {
    handlers []Handler
    upstream string
    client   *fasthttp.HostClient
}

// Thứ tự handlers trong pipeline:
// 1. BlocklistHandler  — check IP trong danh sách đen
// 2. RateLimitHandler  — sliding window per IP
// 3. AnomalyHandler    — record request cho anomaly detector
// Sau đó forward đến upstream
```

### 4.5 Lớp Khiên Bảo Vệ Hệ Thống (Shield Interface)

Để đảm bảo khả năng chạy cross-platform (Development trên Windows/Mac, Production trên Linux), lớp Block L3/L4 được thiết kế qua Interface `Shield`.

**Module: internal/shield/shield.go**

```go
type Shield interface {
    Block(ip string) error
    Unblock(ip string) error
    GetDropCount() int64
    Start() error
    Stop() error
}
```

Go **build tags** sẽ tự động chọn đúng driver để tải lên khi biên dịch:

1. **Linux eBPF Driver** (`//go:build linux`): Sử dụng chương trình XDP C-code để load thẳng vào kernel. Block siêu tốc không tốn cost userspace.
2. **Userspace Driver** (`//go:build !linux`): Chạy map concurrency bằng Go, hook thẳng vào khâu TCP Accept hoặc pipeline đầu vào của fasthttp. Tốc độ chậm hơn eBPF nhưng tương thích 100% các hệ điều hành khác (Windows, macOS).

### 4.6 Module: proxy/server.go

Reverse proxy sử dụng `fasthttp.HostClient` để forward request đến upstream. Cần copy toàn bộ headers, body, và response trả về.

Behavior:
- Listen trên port từ config
- Tích hợp lớp `Shield` vào luồng `ConnState` hoặc Middleware để Block sớm nhất có thể.
- Mỗi request chạy qua Pipeline
- Nếu pipeline pass → forward đến upstream, trả response về client
- Nếu pipeline block → trả status code tương ứng (403, 429)
- Log mọi blocked request với IP, reason, timestamp

### 4.7 Module: ratelimit/limiter.go

Sử dụng **sliding window counter** trong Redis. Không dùng fixed window vì dễ bị boundary attack (gửi 100 req cuối window + 100 req đầu window tiếp theo = 200 req trong 1 giây).

**Algorithm:**
```
key = "noxis:rl:{ip}"
window_start = now - window_seconds * 1000  (milliseconds)

MULTI
  ZREMRANGEBYSCORE key 0 window_start    # xóa entries cũ
  ZCARD key                               # đếm entries hiện tại
  ZADD key now now                        # thêm entry mới
  EXPIRE key window_seconds
EXEC

nếu count >= max_requests → block, return 429
```

**Subnet aggregation:**
- Nếu >= `subnet_threshold` IPs từ cùng /24 subnet bị rate limited → block toàn bộ /24
- Key: `"noxis:subnet:{subnet}"` (ví dụ: `noxis:subnet:192.168.1`)

**Adaptive threshold:**
- IP clean (không bị block) sau 1 giờ → tăng limit thêm 20%
- Key để track: `"noxis:trust:{ip}"` — TTL 1 giờ, reset mỗi lần bị block

### 4.6 Module: blocklist/blocklist.go

Quản lý danh sách IP bị block với TTL tự động expire.

**Redis keys:**
```
noxis:block:{ip}   → value: reason string, TTL: ttl_hours
noxis:allow:{ip}   → value: "1", no TTL (permanent whitelist)
```

**AbuseIPDB integration:**
- Khi IP lần đầu kết nối, check async (không block pipeline)
- Cache kết quả trong Redis: `noxis:abuse:{ip}` TTL 24h
- Nếu score >= threshold → tự động add vào blocklist

**Methods cần implement:**
```go
Block(ip, reason string) error
Unblock(ip string) error
IsBlocked(ip string) (bool, string)  // bool: blocked?, string: reason
Whitelist(ip string) error
IsWhitelisted(ip string) bool
List() []BlockedIP  // để hiển thị trên dashboard
```

### 4.7 Module: anomaly/detector.go

Xây dựng baseline traffic và phát hiện bất thường bằng Z-score.

**Algorithm:**
```
Mỗi giây:
  1. Đếm số request trong giây đó → currentRPS
  2. Thêm vào samples[] (rolling window)
  3. Tính mean và standard deviation của samples[]
  4. zscore = (currentRPS - mean) / stddev
  5. Nếu zscore > threshold → trigger OnAlert callback

Baseline learning:
  - Cần tối thiểu 60 samples (60 giây) trước khi detect
  - Rolling window = baseline_window_minutes * 60 samples
```

**Slowloris detection:**
- Track số connection đang mở mỗi IP
- Nếu IP giữ > max_connections_per_ip connection → flag nghi ngờ

**Callbacks:**
```go
OnAttackDetected func(rps float64, zscore float64)
OnAttackResolved func(duration time.Duration, totalBlocked int64)
```

### 4.8 Module: metrics/prometheus.go

Expose Prometheus metrics tại `/metrics` port 2112.

**Metrics cần expose:**
```
noxis_requests_total{status="passed|blocked"}   Counter
noxis_current_rps                               Gauge
noxis_ebpf_drops_total                          Counter
noxis_banned_ips_total                          Gauge
noxis_active_connections                        Gauge
noxis_attack_detected_total                     Counter
noxis_rate_limit_hits_total                     Counter
noxis_blocklist_hits_total                      Counter
```

### 4.9 Module: websocket/hub.go

Push metrics real-time đến dashboard qua WebSocket.

**Message format (JSON) — push mỗi giây:**
```json
{
  "timestamp": 1710000000000,
  "currentRPS": 326,
  "peakRPS": 3200,
  "totalRequests": 118000,
  "blocked": 24200,
  "passed": 37200,
  "bannedIPs": 407,
  "activeConnections": 77,
  "ebpfDrops": 110100,
  "status": "normal",
  "recentEvents": [
    {
      "time": "13:17:52",
      "type": "attack_detected",
      "detail": "RPS spike: 3637/s (z-score: 6.1)"
    }
  ]
}
```

**Status values:**
- `"normal"` — hoạt động bình thường
- `"under_attack"` — đang bị tấn công
- `"stable"` — vừa kết thúc tấn công

**Hub behavior:**
- Broadcast đến tất cả connected clients mỗi giây
- Auto-cleanup disconnected clients
- Dashboard phải implement auto-reconnect

### 4.10 Module: ebpf/xdp_filter.c

eBPF C program chạy trong kernel. Load bằng `cilium/ebpf`.

**Chức năng:**
- SYN flood protection: track SYN packets per IP, drop nếu vượt rate
- UDP flood protection: drop UDP packets quá ngưỡng
- Blackhole list: BPF map chứa IP bị block ở kernel level

**BPF Maps:**
```c
// Per-IP packet rate tracking
struct bpf_map_def syn_count_map  // key: IP (u32), value: counter

// Kernel-level blocklist (sync từ Go)
struct bpf_map_def blocked_ips    // key: IP (u32), value: 1
```

**Go loader (ebpf/loader.go):**
- Load compiled eBPF object vào kernel khi Noxis start
- Expose method `BlockIP(ip)` để Go sync IP từ blocklist vào BPF map
- Expose method `GetDropCount()` để lấy số packet đã drop

### 4.11 cmd/noxis/main.go

Entrypoint, wire tất cả modules lại:

```
1. Load config (viper)
2. Init logger (zap)
3. Connect Redis
4. Load eBPF program (nếu enabled)
5. Init anomaly detector
6. Init blocklist
7. Init rate limiter
8. Build pipeline: [blocklist, ratelimit, anomaly]
9. Start proxy server (port 8080)
10. Start WebSocket hub (port 9090)
11. Start Prometheus server (port 2112)
12. Start TUI dashboard (terminal)
13. Graceful shutdown on SIGINT/SIGTERM
```

### 4.12 cmd/noxctl/main.go

CLI tool để quản lý Noxis khi đang chạy.

```bash
noxctl block <ip> [--reason "manual"]    # Block IP
noxctl unblock <ip>                       # Unblock IP
noxctl whitelist <ip>                     # Whitelist IP
noxctl list                               # List blocked IPs
noxctl status                             # Xem trạng thái hệ thống
noxctl stats                              # Xem stats hiện tại
```

CLI giao tiếp với Noxis qua Unix socket hoặc HTTP API nội bộ (port 9091).

---

## 5. Frontend — Dashboard

### 5.1 Tech stack

```
Vite 5 + React 18 + TypeScript
├── shadcn/ui        — UI components
├── Recharts         — Traffic chart real-time
├── Zustand          — Global state management
├── clsx + tailwind  — Styling
└── WebSocket API    — Native browser API, không cần lib
```

### 5.2 Design system

**Color palette** (dark theme):
```
Background:   #0a0a0f
Surface:      #111118
Border:       #1e1e2e
Text primary: #e2e8f0
Text muted:   #64748b

Green (passed/normal): #10b981
Red (blocked/attack):  #ef4444
Orange (warning):      #f59e0b
Blue (info):           #3b82f6
Purple (accent):       #8b5cf6
```

**Visual style:**
- Dark theme toàn bộ
- Glassmorphism cho cards: `backdrop-blur`, `bg-white/5`, `border border-white/10`
- Monospace font cho số liệu metrics
- Subtle glow effect khi status "under_attack"

### 5.3 Layout

```
┌─────────────────────────────────────────────────────┐
│  NOXIS  [● NORMAL / ⚠ UNDER ATTACK]     v1.0       │  Header
├──────────┬──────────┬──────────┬────────────────────┤
│ CURR RPS │ BLOCKED  │  PASSED  │    BANNED IPs      │  Metric Cards
│   326    │  24.2K   │  37.2K   │      407           │
├──────────┴──────────┴──────────┴────────────────────┤
│                                                       │
│         TRAFFIC TIMELINE (5 min)                     │  Chart
│         [line chart: passed=green, blocked=red]      │
│                                                       │
├────────────────────────┬────────────────────────────┤
│  SYSTEM HEALTH         │  RECENT EVENTS             │
│  Block Rate: 20% ████  │  13:17 🔴 Attack detected  │
│  Active Conns: 77      │  13:17 🚫 Blocked 24161    │
│  eBPF Drops: 110.1K    │  13:15 ✅ Attack resolved  │
│  Uptime: 2h 58m        │                             │
├────────────────────────┴────────────────────────────┤
│  BLOCKED IPs                              [+ Block]  │
│  IP              Reason        Blocked At  Action   │
│  192.168.1.1     rate_limit    13:12       [Unblock] │
└─────────────────────────────────────────────────────┘
```

### 5.4 TypeScript types

```typescript
// types/metrics.ts

export type NoxisStatus = "normal" | "under_attack" | "stable"

export interface NoxisMetrics {
  timestamp: number
  currentRPS: number
  peakRPS: number
  totalRequests: number
  blocked: number
  passed: number
  bannedIPs: number
  activeConnections: number
  ebpfDrops: number
  status: NoxisStatus
  recentEvents: AttackEvent[]
}

export interface AttackEvent {
  time: string
  type: "attack_detected" | "attack_resolved" | "ip_banned" | "system"
  detail: string
}

export interface BlockedIP {
  ip: string
  reason: string
  blockedAt: string
  expiresAt: string
}

// Chart data point
export interface TrafficPoint {
  time: string
  passed: number
  blocked: number
  rps: number
}
```

### 5.5 Hook: useWebSocket.ts

```typescript
// Behavior:
// - Connect đến ws://localhost:9090/ws khi mount
// - Parse message JSON → NoxisMetrics
// - Auto-reconnect sau 2 giây nếu mất kết nối
// - Track connectionStatus: "connected" | "connecting" | "disconnected"
// - Không throw error khi disconnect, chỉ retry silently

interface UseWebSocketReturn {
  metrics: NoxisMetrics | null
  connectionStatus: "connected" | "connecting" | "disconnected"
  lastUpdate: Date | null
}
```

### 5.6 Hook: useMetrics.ts

```typescript
// Behavior:
// - Nhận metrics từ useWebSocket
// - Maintain history array (last 300 data points = 5 phút)
// - Tính toán derived values:
//   - blockRate = blocked / totalRequests * 100
//   - uptimeString = format từ timestamp
// - Zustand store để share state giữa components

interface MetricsStore {
  current: NoxisMetrics | null
  history: TrafficPoint[]  // last 300 points
  blockRate: number
  uptime: string
  updateMetrics: (m: NoxisMetrics) => void
}
```

### 5.7 Component: TrafficChart.tsx

- Sử dụng Recharts `LineChart`
- 2 lines: `passed` (green `#10b981`) và `blocked` (red `#ef4444`)
- X-axis: time string
- Y-axis: request count
- Animate smooth khi data update
- Show last 300 data points (5 phút)
- Tooltip khi hover

### 5.8 Component: MetricCard.tsx

Props:
```typescript
interface MetricCardProps {
  label: string
  value: string | number
  color?: "green" | "red" | "blue" | "orange"
  subtext?: string
}
```

Style: glassmorphism card, large monospace number, label nhỏ phía trên.

### 5.9 Component: EventFeed.tsx

- Hiển thị `recentEvents` từ metrics
- Auto-scroll xuống khi có event mới
- Icon theo type: 🔴 attack_detected, ✅ attack_resolved, 🚫 ip_banned
- Max 50 events, cũ hơn tự động remove
- Highlight row màu đỏ nhạt khi `attack_detected`

### 5.10 Component: BlocklistTable.tsx

- Fetch blocked IPs từ REST API: `GET /api/blocklist`
- Columns: IP, Reason, Blocked At, Expires At, Action (Unblock button)
- Unblock: `DELETE /api/blocklist/{ip}`
- Manual block: form với IP input + reason
- Refresh mỗi 10 giây

### 5.11 App.tsx

- Single page, không cần routing
- Layout grid như wireframe ở trên
- Show connection status indicator ở header
- Khi `status === "under_attack"`: header glows đỏ, slight pulse animation
- Khi reconnecting: banner nhỏ phía trên "Reconnecting..."

---

## 6. REST API (Go backend)

Ngoài WebSocket, backend cũng cần expose REST API cho dashboard quản lý:

```
GET  /api/status           # System status overview
GET  /api/blocklist        # List blocked IPs
POST /api/blocklist        # Block IP: body {ip, reason}
DEL  /api/blocklist/:ip    # Unblock IP
GET  /api/whitelist        # List whitelisted IPs
POST /api/whitelist        # Whitelist IP
DEL  /api/whitelist/:ip    # Remove from whitelist
GET  /api/stats            # Detailed stats
```

Tất cả trả về JSON. Dùng `net/http` standard library hoặc `fasthttp` routing.

---

## 7. Docker Compose

```yaml
version: "3.8"
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    ports:
      - "127.0.0.1:6379:6379"

  noxis:
    build: .
    restart: unless-stopped
    network_mode: host  # Cần host network cho eBPF/XDP
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - ./config:/etc/noxis
    depends_on:
      - redis
```

---

## 8. Build & development

### Build Go binary
```bash
go build -o noxis ./cmd/noxis
go build -o noxctl ./cmd/noxctl
```

### Build eBPF (cần clang)
```bash
clang -O2 -target bpf -c ebpf/xdp_filter.c -o ebpf/xdp_filter.o
```

### Build dashboard
```bash
cd dashboard
npm install
npm run build    # output ra dashboard/dist/
```

### Development
```bash
# Terminal 1: Go backend
go run ./cmd/noxis

# Terminal 2: Dashboard dev server
cd dashboard && npm run dev
```

---

## 9. Thứ tự implement (Phase)

### Phase 1 — Core pipeline (tuần 1-2)
1. `internal/proxy/pipeline.go` — Handler interface
2. `internal/proxy/server.go` — fasthttp reverse proxy
3. `internal/ratelimit/limiter.go` — sliding window Redis
4. `internal/blocklist/blocklist.go` — TTL blocklist
5. `cmd/noxis/main.go` — wire modules, server chạy được
6. Test: curl đơn giản, verify proxy hoạt động

### Phase 2 — Intelligence (tuần 3)
1. `internal/anomaly/detector.go` — Z-score detector
2. `internal/websocket/hub.go` — WebSocket push
3. AbuseIPDB integration trong blocklist
4. Subnet aggregation trong rate limiter

### Phase 3 — Dashboard (tuần 4)
1. Vite + React scaffold
2. `useWebSocket.ts` + `useMetrics.ts`
3. `MetricCard`, `TrafficChart`, `EventFeed` components
4. `BlocklistTable` + REST API
5. Responsive layout + dark theme

### Phase 4 — Observability & eBPF (tuần 5)
1. Prometheus metrics exporter
2. eBPF/XDP filter (C + Go loader)
3. `cmd/noxctl` CLI tool
4. Docker Compose setup
5. README + documentation

---

## 10. Lưu ý quan trọng

1. **eBPF cần Linux** — không chạy được trên macOS. Development local dùng mock, production deploy lên Linux VPS.

2. **Redis phải chạy trước Noxis** — nếu Redis down, rate limiter fail open (cho qua hết) thay vì fail closed (block hết). Đây là intentional behavior để tránh self-DDoS.

3. **Dashboard phải survive attack** — WebSocket server chạy trên port riêng (9090), độc lập với proxy port (8080). Ngay cả khi proxy đang chịu tải nặng, dashboard vẫn nhận được data.

4. **Không expose upstream trực tiếp** — Firewall rule: chỉ Noxis mới connect được đến upstream port. Dùng `iptables` hoặc `ufw` để enforce.

5. **Config hot reload** — Viper hỗ trợ watch config file. Rate limit threshold và blocklist TTL nên reload được mà không cần restart.

6. **Graceful shutdown** — Khi nhận SIGTERM: dừng nhận request mới, chờ in-flight requests xử lý xong (timeout 30s), rồi shutdown.
