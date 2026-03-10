# NOXIS — Project Specification Document
> Tài liệu này mô tả toàn bộ dự án Noxis Shield 3-in-1 Engine.
> Đây là bản đặc tả kỹ thuật chính thức (Đã được cập nhật sau quá trình cài đặt thực tế).

---

## 1. Tổng quan dự án

**Tên dự án:** Noxis Shield
**Tagline:** L3/L4/L7 DDoS Mitigation Engine — Traffic filtering from the shadows
**GitHub:** `github.com/8w6s/noxis_shield`
**Ngôn ngữ backend:** Go 1.22
**Ngôn ngữ frontend:** HML5 + Vanilla JS + CSS3 (Glassmorphism)
**Frontend framework:** Không (Sử dụng `go:embed` để tích hợp tĩnh)

Noxis là một reverse proxy thông minh đứng trước ứng dụng của người dùng, lọc toàn bộ traffic độc hại trước khi nó đến được upstream app. Hệ thống hoạt động trên Linux VPS, sử dụng eBPF/XDP để lọc ở kernel-level (L3/L4) và Go userspace để xử lý L7. Đồng thời, Noxis có trang bị Web UI Dashboard Premium theo dõi thời gian thực.

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
│  Port 9090 — Web UI & WebSocket │
│  Port 9091 — Admin API (Local)  │
└────────────┬─────────────────────┘
             │ Verified clean traffic
             ▼
┌──────────────────────────────────┐
│  Upstream App                   │
│  (chạy localhost, không expose) │
└──────────────────────────────────┘
```

### 2.2 Deployment topology

```
VPS (Linux, Ubuntu 22.04+)
├── Noxis binary (Tự động host cả Proxy, Admin API và Web Dashboard tĩnh)
├── Redis (localhost:6379) — rate limit state
└── Upstream app (localhost:3000) — app người dùng
```

---

## 3. Cấu trúc thư mục

```
noxis_shield/
├── cmd/
│   ├── noxis/
│   │   └── main.go                 # Entrypoint chính của Noxis Engine
│   └── noxctl/
│       └── main.go                 # CLI tool quản lý proxy nội bộ
├── internal/
│   ├── proxy/
│   │   ├── pipeline.go             # Middleware chain (L7)
│   │   └── server.go               # fasthttp reverse proxy server
│   ├── ratelimit/
│   │   ├── limiter.go              # Redis Sliding Window Rate Limiter
│   │   └── handler.go              # Rate limit pipeline hook
│   ├── blocklist/
│   │   ├── blocklist.go            # IP blocklist ruleset (Redis Backend)
│   │   └── handler.go              # Blocklist pipeline hook
│   ├── anomaly/
│   │   ├── detector.go             # Z-score Anomaly baseline AI
│   │   └── handler.go              # Anomaly pipeline hook
│   ├── metrics/
│   │   ├── aggregator.go           # Tập hợp các chỉ số theo atomic memory
│   │   └── prometheus.go           # Prometheus exporter (/metrics)
│   ├── websocket/
│   │   └── hub.go                  # Broadcast data sang giao diện web (Port 9090)
│   ├── shield/
│   │   ├── shield.go               # Interface trừu tượng L3/L4 Proxy
│   │   ├── ebpf_linux.go           # Driver móc nối XDP (Linux only)
│   │   └── userspace.go            # Driver dùng Map mô phỏng (Windows/Mac)
│   ├── admin/
│   │   └── server.go               # Localhost admin API handler
│   └── dashboard/
│       ├── server.go               # HTTP fileserver nhúng file tĩnh
│       └── web/                    # Giao diện Web HTML/CSS/JS thuần
│           ├── index.html
│           ├── style.css
│           └── app.js
├── ebpf/
│   └── xdp_filter.c                # eBPF C program (kernel code)
├── config/
│   ├── config.go                   # Khởi tạo VIPER env
│   └── noxis.yaml                  # Config mặc định
├── attack.go                       # Kịch bản mô phỏng tấn công HTTP Flood
├── docker-compose.yml              # Dàn trận tự động Redis + Noxis
├── Dockerfile                      # Trình build hai lớp (Builder + Runner)
├── noxis_architecture.md           # Giải thuật cốt lõi
├── README.md
└── NOXIS_SPEC.md
```

---

## 4. Đặc điểm Kỹ Thuật Chính

- **Platform Agnostic eBPF/Userspace:** Tự động fallback sang driver mảng/hashmap của Golang nếu chạy trên Windows (Userspace). Khi trên Linux Server, chương trình được biên dịch cùng thư viện bpf2go của Cilium để đính mã C vào thẳng card mạng.
- **Embedded Web Dashboard:** Màn hình điều khiển được nhúng chung vào file `.exe` / `binary` cuối cùng. Góp phần giảm tải dependency (Không cần Nextjs, Nginx hay Caddy). Mở file là có sẵn.
- **Fail-open Logic:** Redis lỗi? Noxis sẽ hoạt động ở chế độ fail-open pass all data để cứu server thay vì đánh sập cả cụm.
- **NoxCtl Command-line Interface:** Một tiện ích command gõ tay để Block/Unblock IP nhanh gọn lẹ mà không sợ lộ API (Admin API chỉ mở trên 127.0.0.1).

---

## 5. Build & deployment

### Build Go binary & eBPF
```bash
# Go tự gọi trình generate BPF trước, sau đó build
go generate ./...
go build -o noxis ./cmd/noxis
go build -o noxctl ./cmd/noxctl
```

### Chạy hệ thống trên Docker (Production)
```bash
docker-compose up -d --build
```

### Chạy phát triển (Development)
```bash
# Terminal 1: Phát sinh server mục tiêu
python3 -m http.server 3000

# Terminal 2: Chạy proxy engine Noxis (Tự load HTML)
go run ./cmd/noxis

# Mở trình duyệt xem Control Panel Web
http://localhost:9090/
```

### Test Tấn công & Hệ thống tự vệ (Z-Score)
```bash
# Chạy Flood attack
go run attack.go
```
Khi chạy, Rate Limiter sẽ từ chối truy cập (429) và Z-Score Alert sẽ đổi UI sang nhấp nháy Đỏ.
