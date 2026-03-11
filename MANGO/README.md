# 🥭 Mango Shield v2.0

> **Hệ thống chống DDoS Layer 7 & WAF tự triển khai — Bảo vệ nhiều domain cùng lúc**

---

## 📋 Mục lục

1. [Tổng quan](#-tổng-quan)
2. [Cài đặt từ đầu (VPS mới)](#-cài-đặt-từ-đầu-vps-mới)
3. [Cấu hình nhiều domain](#-cấu-hình-nhiều-domain)
4. [Các chế độ bảo vệ](#️-các-chế-độ-bảo-vệ)
5. [Quản lý bằng CLI](#-quản-lý-bằng-cli)
6. [Dashboard](#-dashboard)
7. [Cấu hình chi tiết](#️-cấu-hình-chi-tiết)
8. [Cấu trúc dự án](#-cấu-trúc-dự-án)
9. [API Endpoints](#-api-endpoints)
10. [WAF Rules](#-waf-rules)
11. [Cảnh báo Telegram](#-cảnh-báo-telegram)
12. [Docker](#-docker)
13. [Xử lý sự cố](#-xử-lý-sự-cố)

---

Mango Shield bảo vệ website của bạn khỏi tấn công DDoS Layer 7 bằng mô hình **phòng thủ đa tầng (Defense in Depth)** tiên tiến:

```
Người dùng → [Mango Shield] → Website gốc (Backend)

Lớp 0: XDP/eBPF Acceleration (Lớp 4) — Chặn IP ở tầng nhân/phần cứng (10M RPS)
Lớp 1: TLS Early Reject (Lớp 7 sớm) — Ngắt kết nối Botnet trước khi giải mã HTTPS
Lớp 2: TLS Fingerprint (JA3/JA4) — Nhận dạng và chấm điểm mức độ tin cậy của Client
Lớp 3: Tình báo IP & Reputation — GeoIP, ASN, Threat Feeds (50k+ IP xấu)
Lớp 4: WAF (Layer 7) — Chặn SQLi, XSS, LFI, RCE (Core 28 OWASP Rules)
Lớp 5: Thử thách JS PoW — Xác minh người dùng thật, không cần CAPTCHA ngoài
Lớp 6: Phân tích Hành vi (Behavior) — AI tự động nhận diện mẫu tấn công mới
Lớp 7: Học thích ứng & Thoái giáng — Tự duy trì dịch vụ khi bị overload
Lớp 8: Smart CDN Caching — Đệm nội dung tĩnh trên RAM (Ristretto) tăng tốc cực nhanh
Lớp 9: Upstream Load Balancing — Rải tải thông minh (Round-Robin) tới nhiều Backend
Lớp 10: Mango P2P Mesh — Đồng bộ Danh sách đen (Ban/Whitelist) giữa các Node không cần Redis
```

**Hỗ trợ:**
- ✅ HTTP & HTTPS
- ✅ IP trần & Domain
- ✅ Nhiều domain → nhiều backend khác nhau (Load Balancing)
- ✅ WebSocket pass-through
- ✅ Let's Encrypt (hướng dẫn bên dưới)
- ✅ **CDN Smart Caching** (Chỉ cache file tĩnh, an toàn mọi Website)
- ✅ **Gossip Protocol Cluster** (Chạy cụm đa VPS không cần cấu hình DB)
- ✅ Hỗ trợ Environment Variables (`viper`) cho Docker và CI/CD

---

## 🚀 Cài đặt từ đầu (VPS mới)

### Bước 1: Cài Go (nếu chưa có)

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y golang-go git

# Hoặc cài Go mới nhất
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Kiểm tra
go version
```

### Bước 2: Tải mã nguồn

```bash
# Clone từ GitHub
git clone https://github.com/hoangtuvungcao/mango-waf.git /opt/mango-shield

# Hoặc upload từ máy local
# scp -r mango-waf/ root@YOUR_VPS_IP:/opt/mango-shield/
```

### Bước 3: Tối ưu hóa hệ thống (Khuyên dùng cho DDoS lớn)

```bash
cd /opt/mango-shield

# 1. Tối ưu Linux TCP Stack (Mở rộng file descriptors, tối ưu socket)
chmod +x scripts/optimize_tcp.sh
sudo ./scripts/optimize_tcp.sh

# 2. Cài đặt XDP/eBPF (Hỗ trợ chặn 1 Triệu RPS - Yêu cầu Linux 5.10+)
chmod +x xdp/setup_xdp.sh
sudo ./xdp/setup_xdp.sh
```

### Bước 4: Biên dịch

```bash
# Biên dịch server chính
go build -o mango-shield .

# Biên dịch CLI quản lý
go build -o mango-cli ./cmd/cli/

# Kiểm tra
./mango-shield -version
```

### Bước 4: Tạo file cấu hình

```bash
# Sao chép file mẫu
cp config/default.yaml config/config.yaml

# Chỉnh sửa cấu hình (xem phần "Cấu hình nhiều domain" bên dưới)
nano config/config.yaml
```

### Bước 5: Chạy thử

```bash
# Chạy trực tiếp để test (Ctrl+C để dừng)
./mango-shield -config config/config.yaml
```

### Bước 6: Cài systemd service (production)

```bash
# Sao chép service file
sudo cp deploy/mango-shield.service /etc/systemd/system/

# Kích hoạt và khởi động
sudo systemctl daemon-reload
sudo systemctl enable mango-shield
sudo systemctl start mango-shield

# Kiểm tra trạng thái
sudo systemctl status mango-shield

# Xem log thời gian thực
sudo journalctl -u mango-shield -f
```

### Bước 7: Mở firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 9090/tcp    # Dashboard (nên giới hạn IP truy cập)

# Hoặc iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
```

---

## 🌐 Cấu hình nhiều domain

### Cách hoạt động

```
                      ┌─ example.com ───────→ backend :8080 (Web chính)
                      │
Client → Mango ───────┼─ api.example.com ──→ backend :3000 (API server)
Shield (port 80/443)  │
                      ├─ khachhang-a.com ──→ backend :8081 (Khách A)
                      │
                      └─ khachhang-b.com ──→ backend :8082 (Khách B)
```

Mango Shield tự nhận diện domain từ `Host` header và chuyển tiếp đến đúng backend.

### Ví dụ 1: Một domain, một backend

```yaml
# Đơn giản nhất — 1 website
domains:
  - name: "example.com"
    upstreams:
      - url: "http://127.0.0.1:8080"
```

### Ví dụ 2: Nhiều domain → nhiều backend (cho nhiều người dùng)

```yaml
# Mỗi domain/khách hàng có backend riêng
domains:
  # Website chính của bạn
  - name: "example.com"
    upstreams:
      - url: "http://127.0.0.1:8080"

  # API server
  - name: "api.example.com"
    upstreams:
      - url: "http://127.0.0.1:3000"

  # Website khách hàng A
  - name: "khachhang-a.com"
    upstreams:
      - url: "http://127.0.0.1:8081"
```

### Ví dụ 3: Load Balancing (Nhiều backend cho tỷ lệ tải)

```yaml
# Chia tải ra nhiều backend (Round-Robin tự động)
domains:
  - name: "web.example.com"
    upstreams:
      - url: "http://localhost:8080"        # Server A
      - url: "http://localhost:8081"        # Server B
      - url: "http://10.0.0.5:8080"         # Server Mạng nội bộ
```

### Ví dụ 4: IP trần (chưa có domain)

```yaml
tls:
  enabled: false       # Không dùng HTTPS khi dùng IP trần

domains:
  - name: "103.77.246.172"
    upstreams:
      - url: "http://127.0.0.1:8080"
```

### Ví dụ 5: HTTPS với Let's Encrypt (production)

```bash
# 1. Cài certbot
sudo apt install certbot

# 2. Tạm dừng Mango Shield (certbot cần port 80)
sudo systemctl stop mango-shield

# 3. Lấy cert
sudo certbot certonly --standalone \
  -d example.com \
  -d api.example.com \
  -d khachhang-a.com

# 4. Cấu hình TLS trong config.yaml:
```

```yaml
tls:
  enabled: true
  cert_file: "/etc/letsencrypt/live/example.com/fullchain.pem"
  key_file: "/etc/letsencrypt/live/example.com/privkey.pem"
```

```bash
# 5. Khởi động lại
sudo systemctl start mango-shield

# 6. Tự động gia hạn cert (cron job)
echo "0 3 * * * certbot renew --pre-hook 'systemctl stop mango-shield' --post-hook 'systemctl start mango-shield'" | sudo tee -a /etc/crontab
```

---

### Chế độ Auto (Tự động - Khuyên dùng)
Hệ thống tự động chấm điểm IP dựa trên 10 lớp bảo vệ. 
- **Chế độ Seamless (Mượt mà):** Nếu bạn là người dùng thật, hệ thống sẽ cho qua ngay lập tức mà không hiện bất kỳ thông báo nào.
- **JS Challenge:** Chỉ bật lên khi RPS của IP đó tăng cao hoặc vân tay có dấu hiệu nghi vấn (Bot).
- **CAPTCHA:** Chỉ xuất hiện khi có bằng chứng xác thực về việc bị tấn công dồn dập (DDoS mạnh).

---

## 🕸️ Cụm Đa Máy Chủ (Mango Mesh)

Để chống lại các đợt DDoS khổng lồ, Mango Shield cho phép kết nối nhiều VPS thành một mạng lưới Mesh đồng bộ.

### 1. Đồng bộ Danh sách đen (Ban/Whitelist)
Khi Node A chặn một IP, Node B và C sẽ tự động chặn IP đó ngay lập tức mà không cần database trung tâm.

### 2. Chia sẻ phiên làm việc (Session Sharing)
Nếu người dùng đã xác minh ở Node A, khi họ chuyển sang Node B (do DNS Round-Robin), họ sẽ **không phải giải lại challenge**. Điều này yêu cầu `cookie_secret` trong file cấu hình phải giống hệt nhau trên tất cả các Node.

### 3. Cấu hình Mesh (P2P Gossip)
Mở cổng `7946` (cả TCP và UDP) trên tất cả các VPS để chúng có thể "nói chuyện" với nhau.

```yaml
cluster:
  enabled: true
  node_name: "vps-1"
  bind_port: 7946
  advertise_ip: "103.77.246.172"
  secret_key: "AES-32-KHOA-CUA-RIENG-BAN-!!" # Giống nhau mọi Node
  join_peers: ["IP_CUA_NODE_DA_CO:7946"]
```
# === NHẬN DẠNG ===
fingerprint:
  ja3:
    enabled: true
  ja4:
    enabled: true
  http2:
    enabled: true

# === TÌNH BÁO ===
intelligence:
  geoip:
    enabled: true
    db_path: "/etc/mango/GeoLite2-City.mmdb"
    blocked_countries: []            # VD: ["CN","RU"]
  ip_reputation:
    enabled: true
    abuseipdb_key: "YOUR_KEY"        # https://abuseipdb.com/register
  asn:
    enabled: true

# === PHÁT HIỆN ===
detection:
  baseline:
    enabled: true
    learning_period: 24h
  anomaly:
    enabled: true
    sensitivity: 0.7
  bot_classifier:
    enabled: true

# === WAF ===
waf:
  enabled: true
  owasp_rules: true
  paranoia_level: 2                  # 1=cơ bản, 2=tiêu chuẩn, 3=nghiêm ngặt

# === LOG ===
logging:
  level: "info"
  format: "json"
  file: "/var/log/mango-shield.log"

# === DASHBOARD ===
dashboard:
  enabled: true
  listen: "127.0.0.1:9090"
  username: "admin"
  password: "matkhaumanh123"

# === CẢNH BÁO ===
alerts:
  telegram:
    enabled: true
    token: "BOT_TOKEN"               # Từ @BotFather
    chat_id: "CHAT_ID"              # Từ @userinfobot
  discord:
    enabled: false
    webhook_url: ""
```

### Tải lại cấu hình (không restart)

```bash
kill -HUP $(pidof mango-shield)
```

---

## 📁 Cấu trúc dự án

```
mango-waf/
├── scripts/                    # TỐI ƯU HỆ THỐNG
│   └── optimize_tcp.sh         # Script tối ưu Sysctl cho High Concurrency
├── xdp/                        # LỚP PHÒNG THỦ CỨNG
│   ├── mango_xdp.c             # Mã nguồn C (eBPF)
│   ├── setup_xdp.sh            # Script cài đặt compiler & nạp XDP
│   └── SETUP_XDP.md            # Hướng dẫn chi tiết XDP
├── main.go                     # Điểm vào — khởi tạo 10 hệ con
├── cmd/cli/main.go             # CLI quản lý (tiếng Việt)
│
├── config/
│   ├── config.go               # Tải YAML, hot-reload, validate
│   └── deploy.yaml             # Cấu hình mẫu cho VPS
│
├── core/                       # LÕI HỆ THỐNG
│   ├── server.go               # TLS server, xử lý HTTP
│   ├── pipeline.go             # Pipeline bảo vệ đa tầng
│   ├── xdp.go                  # Go manager cho eBPF Maps
│   ├── proxy.go                # Reverse proxy, WebSocket
│   ├── challenge.go            # Thử thách JS/CAPTCHA
│   └── alerts.go               # Telegram/Discord/Webhook alerts
│
├── fingerprint/                # NHẬN DẠNG TRÌNH DUYỆT
│   ├── fingerprint.go          # Kiểu dữ liệu, chấm điểm
│   ├── early_reject.go         # SSL Sniffing & Early Drop logic
│   ├── tls_parser.go           # Phân tích TLS ClientHello
│   ├── h2_parser.go            # Phân tích HTTP/2 frames
│   ├── database.go             # 100+ fingerprint Botnet & Browser
│   ├── interceptor.go          # Chặn kết nối TLS StdLib
│   └── silent_js.go            # Nhận dạng trình duyệt ẩn
│
├── intelligence/               # TÌNH BÁO IP
│   ├── intelligence.go         # Engine đánh giá 5 lớp
│   ├── reputation.go           # AbuseIPDB API
│   ├── asn.go                  # Phân loại nhà mạng (70+)
│   └── feeds.go                # 8 nguồn dữ liệu mối đe dọa
│
├── detection/                  # PHÁT HIỆN TẤN CÔNG
│   ├── detection.go            # Baseline & anomaly
│   ├── behavior.go             # Hành vi 6 yếu tố
│   ├── classifier.go           # Phân loại bot (13 chữ ký)
│   ├── signatures.go           # 10 mẫu tấn công
│   └── adaptive.go             # Tự học traffic 24h
│
├── challenge/                  # THỬ THÁCH v2
│   ├── challenge.go            # Manager PoW/Turnstile/reCAPTCHA
│   └── templates.go            # Template UI glassmorphism
│
├── rules/                      # WAF ENGINE
│   ├── engine.go               # Rules engine, inspector
│   ├── owasp.go                # 28 rule OWASP CRS
│   └── custom.go               # Tải rule tùy chỉnh YAML
│
├── api/
│   └── dashboard.go            # REST API + dashboard nhúng
│
├── perf/                       # HIỆU SUẤT
│   ├── pool.go                 # Rate limiter, memory manager
│   └── hardening.go            # Header bảo mật, thoái giáng
│
├── logger/
│   └── logger.go               # Ghi log có cấu trúc (zap)
│
├── deploy/
│   └── mango-shield.service    # Systemd service
├── Dockerfile                  # Docker multi-stage
└── docker-compose.yml          # Docker Compose
```

---

## 🕸️ Cài đặt Cụm Đa Máy Chủ (Mango P2P Mesh)

Để chống lại các đợt DDoS khổng lồ (vượt quá giới hạn băng thông 10Gbps của 1 VPS), bạn có thể chạy Mango Shield trên nhiều máy chủ khác nhau. Tính năng **Mango Mesh** sẽ kết nối chúng lại bằng giao thức Gossip (không cần Redis!).

Khi **VPS 1 (Hà Nội)** chặn IP `1.2.3.4`, nó sẽ báo ngay cho **VPS 2 (Hồ Chí Minh)** và **VPS 3 (Singapore)** chặn theo trong vòng vài Mili-giây.

### Bước 1: Mở Port giao tiếp P2P
Trên TẤT CẢ các VPS, bạn phải mở port `7946` cho cả `TCP` và `UDP`:
```bash
sudo ufw allow 7946/udp
sudo ufw allow 7946/tcp
```

### Bước 2: Cấu hình VPS 1 (Máy chủ chính - Node Mỏ Neo)
Ví dụ VPS 1 có IP là `103.77.246.172`. Mở file `config/deploy.yaml`:
```yaml
cluster:
  enabled: true
  node_name: "vps-1-hanoi"
  bind_port: 7946
  advertise_ip: "103.77.246.172" # BẮT BUỘC để báo hệ thống biết IP Public thực sự
  secret_key: "VUI_LONG_DOI_KHOA_BAO_MAT_NAY_THANH_32_BYTE!" # BẮT BUỘC ĐÚNG 32 BYTE & GIỐNG NHAU MỌI VPS
  join_peers: [] # Node đầu tiên làm mỏ neo nên không cần nối tới ai
```

### Bước 3: Cấu hình VPS 2 (Máy chủ phụ 1)
Ví dụ VPS 2 có IP là `103.77.246.153`. Mở file `config/deploy.yaml`:
```yaml
cluster:
  enabled: true
  node_name: "vps-2-hcm"
  bind_port: 7946
  advertise_ip: "103.77.246.153"
  secret_key: "VUI_LONG_DOI_KHOA_BAO_MAT_NAY_THANH_32_BYTE!" # Phải y hệt VPS 1 (32 Byte)
  join_peers: 
    - "103.77.246.172:7946" # Trỏ về IP của VPS 1 để xin gia nhập mạng lưới Mesh
```

### Bước 4: Cấu hình DNS Domain (Load Balancing & Failover trên 2 Server)
Để website của bạn có thể sử dụng sức mạnh tính toán của cả 2 máy chủ cùng lúc, hãy cấu hình bản ghi DNS (trên Cloudflare, v.v...) theo dạng **Round-Robin**:
- Trỏ **2 bản ghi `A`** cùng tên miền về 2 IP khác nhau của Cụm Mango Mesh.


Khởi động lại Mango Shield trên cả 2 VPS: `sudo systemctl restart mango-shield`. 
Kiểm tra Dashboard API trên VPS 1: `curl -u admin:admin123 http://103.77.246.172:9090/api/stats` bạn sẽ thấy dòng `"mesh_nodes": 2` tức là 2 máy đã kết nối thành công!

**Ví dụ thiết lập trên Cloudflare (Tắt đám mây cam - Tích xám DNS Only):**
| Loại (Type) | Tên (Name) | Nội dung (Content / IP) | TTL |
|---|---|---|---|
| A | `@` | `103.77.246.172` | Auto |
| A | `@` | `103.77.246.153` | Auto |
| A | `www` | `103.77.246.172` | Auto |
| A | `www` | `103.77.246.153` | Auto |

**Luồng hoạt động thực tế:**
1. Khi khách truy cập trang web, hệ thống DNS sẽ tự động chia đều lượt truy cập 50-50 cho mỗi máy chủ. Cực kỳ tối ưu cho CPU.
2. Nếu 1 Server bị đánh sập hoặc đứt mạng, DNS sẽ tự động loại nó ra và đẩy khách sang Server còn lại.
3. Chặn chéo P2P: Nếu hacker tấn công HTTP Flood vào Server 2 và bị cấm IP, mạng Mango Mesh sẽ ngay lập tức đồng bộ danh sách đen (Blacklist) của IP đó về Server 1. Cả cụm được chia sẻ chung một lá chắn!

---

## 📡 API Endpoints

Dashboard API mặc định port `9090`:

| Endpoint | Method | Mô tả | Lệnh test |
|---|---|---|---|
| `/` | GET | Giao diện dashboard | `curl http://IP:9090/` |
| `/api/stats` | GET | Thống kê real-time | `curl http://IP:9090/api/stats` |
| `/api/health` | GET | Kiểm tra sức khỏe | `curl http://IP:9090/api/health` |
| `/api/config` | GET | Cấu hình đang chạy | `curl http://IP:9090/api/config` |
| `/api/rps-history` | GET | Biểu đồ RPS 5 phút | `curl http://IP:9090/api/rps-history` |

---

## 🧱 WAF Rules

### 28 quy tắc OWASP CRS tích hợp sẵn

| Danh mục | Rules | Phát hiện |
|---|:---:|---|
| SQL Injection | 6 | UNION SELECT, tautology, stacked queries, comment bypass |
| XSS | 4 | Script tags, event handlers, eval(), img/iframe |
| LFI | 3 | Path traversal `../`, /etc/passwd, .env, .git |
| RCE | 4 | Unix/Windows command injection, PHP/Node.js |
| RFI | 1 | URL inclusion (http://, php://, data://) |
| SSRF | 1 | Truy cập 127.0.0.1, 10.x, 192.168.x, metadata |
| Scanner | 2 | Nikto, sqlmap, nuclei, Burp Suite |
| Protocol | 3 | HTTP smuggling, invalid methods, null bytes |

### Thêm rule tùy chỉnh

Tạo file `custom-rules.yaml`:

```yaml
rules:
  - id: "CUSTOM-001"
    name: "Block WP login brute force"
    category: "custom"
    severity: "high"
    targets: ["URL"]
    operator: "contains"
    pattern: "/wp-login.php"
    action: "challenge"
    enabled: true

  - id: "CUSTOM-002"
    name: "Block admin paths"
    category: "custom"
    severity: "medium"
    targets: ["URL"]
    operator: "rx"
    pattern: "/(admin|phpmyadmin|manager)"
    action: "block"
    enabled: true
```

Cấu hình:
```yaml
waf:
  custom_rules_path: "/opt/mango-shield/custom-rules.yaml"
```

---

## 🔔 Cảnh báo Telegram

### Cách thiết lập

```
1. Mở Telegram → tìm @BotFather
2. Gửi /newbot → đặt tên → nhận TOKEN
3. Mở @userinfobot → nhận CHAT_ID
4. Điền vào config:
```

```yaml
alerts:
  telegram:
    enabled: true
    token: "123456:ABC-DEF..."      # Token từ @BotFather
    chat_id: "5805939083"           # Chat ID từ @userinfobot
```

### Mẫu cảnh báo nhận được

```
🚨 CẢNH BÁO TẤN CÔNG DDoS
━━━━━━━━━━━━━━━━━━━━━

⏰ Thời gian: 10:00:00 — 05/03/2026
🌐 Domain: example.com
📊 RPS hiện tại: 500 req/s
⚡ Ngưỡng cảnh báo: 200 req/s
📈 Vượt ngưỡng: 2.5x

🔴 Trạng thái: Đang bị tấn công
🛡️ Hành động: Tự động nâng cấp bảo vệ

━━━━━━━━━━━━━━━━━━━━━
🥭 Mango Shield v2.0
```

---

## 🐳 Docker

```bash
# Build image
docker build -t mango-shield .

# Chạy container
docker run -d --name mango-shield \
  -p 443:443 -p 80:80 -p 9090:9090 \
  -v ./config:/app/config:ro \
  -v ./certs:/app/certs:ro \
  --cap-add NET_ADMIN \
  mango-shield

# Hoặc dùng Docker Compose
docker-compose up -d

# Xem log
docker logs -f mango-shield
```

---

## 🔧 Xử lý sự cố

### Server không khởi động — port bị chiếm

```bash
# Tìm process chiếm port
ss -tlnp | grep ':80\|:443\|:9090'

# Giải phóng port
sudo kill $(sudo lsof -t -i:80)

# Hoặc tắt nginx/apache nếu đang chạy
sudo systemctl stop nginx
sudo systemctl stop apache2
```

### Bad Gateway — backend không phản hồi

```bash
# Kiểm tra backend có chạy không
curl -v http://127.0.0.1:8080

# Kiểm tra log Mango Shield
tail -50 /var/log/mango-shield.log

# Đảm bảo backend URL trong config đúng
# Sai: backend: "127.0.0.1:8080"        (thiếu http://)
# Đúng: backend: "http://127.0.0.1:8080"
```

### Tải lại cấu hình (không cần restart)

```bash
kill -HUP $(pidof mango-shield)
```

### Restart hoàn toàn

```bash
sudo systemctl restart mango-shield
```

### Kiểm tra sức khỏe

```bash
curl http://127.0.0.1:9090/api/health
# Mong đợi: {"status":"healthy","version":"2.0.0",...}

# CLI
./mango-cli health
```

### Xem log tấn công

```bash
sudo journalctl -u mango-shield -f --grep="attack\|blocked\|banned"
```

---

## 📜 Giấy phép

MIT License — Được xây dựng với ❤️ bởi Mango Team.
