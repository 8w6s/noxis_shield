# Kế Hoạch Triển Khai Chi Tiết: Noxis Shield

Tài liệu này phân rã chi tiết quá trình phát triển dự án **Noxis**, đảm bảo đáp ứng được đúng định hướng 3-trong-1: **Shield (Lớp chặn Kernel eBPF)**, **Framework (Lớp xử lý userspace L7 bằng Go)**, và **Web Dash Realtime (Lớp giám sát 1 giây/lần)**.

---

## Phase 1: Core Framework & Proxy Foundation (Nền tảng Go L7)
**Mục tiêu:** Xây dựng phần khung (Framework) của một High-Performance Reverse Proxy bằng `fasthttp`. Lớp này nhận traffic, chuyển tiếp an toàn tới Upstream và trả response về.

**Chi tiết công việc (Tasks):**
1. **Khởi tạo Project & Cấu trúc:**
   - `go mod init` và cài đặt dependencies (`fasthttp`, `viper`, `zap`).
   - Tạo cấu trúc thư mục chuẩn theo đặc tả (`cmd/noxis`, `internal/proxy`, `config`, v.v.).
2. **Configuration & Logging:**
   - Dùng `viper` để parse cấu hình từ `config/noxis.yaml` (port, upstream url, timeout).
   - Thiết lập `zap` logger cho ra format JSON siêu nhanh để phục vụ debug và export log.
3. **Core fasthttp Server (`internal/proxy/server.go`):**
   - Tạo listener trên cổng proxy (VD: 8080).
   - Setup `fasthttp.HostClient` để forward request tới Upstream.
   - Viết cơ chế copy headers, body từ Client -> Proxy -> Upstream và ngược lại.
4. **Middleware Pipeline Pattern (`internal/proxy/pipeline.go`):**
   - Định nghĩa `Handler` interface để dễ dàng cắm (plug-in) các module lọc (rate-limit, blocklist) vào request flow.
   - Cho phép các handler ngắt luồng (short-circuit) và trả về HTTP 403/429 lập tức nếu phát hiện bất thường.
5. **Graceful Shutdown:** Bắt signal `SIGINT/SIGTERM` để xả hết request đang pending xử lý trước khi tắt proxy, không làm rớt kết nối đột ngột của người dùng hợp lệ.

---

## Phase 2: The Shield - Platform Agnostic Kernel/Userspace Drop
**Mục tiêu:** Xây dựng Interface `Shield` để chặn đứng traffic tấn công dồn dập ở tầng sớm nhất có thể. Đảm bảo code chạy được trên cả Linux (dùng eBPF siêu nhanh) và Windows/Mac (dùng Userspace chặn qua fasthttp).

**Chi tiết công việc (Tasks):**
1. **Shield Interface (`internal/shield/shield.go`):**
   - Thiết kế interface chuẩn: `Block(ip)`, `Unblock(ip)`, `Start()`, `Stop()`.
2. **Userspace Driver (`internal/shield/userspace.go` - Phục vụ Windows/Mac):**
   - Sử dụng concurrency map (VD: `sync.Map` hoặc RWMutex) để lưu IP blacklist.
   - Hook vào `fasthttp.ConnState` hoặc pipeline sớm nhất để ngắt kết nối `net.Conn` ngay lập tức nếu IP nằm trong blacklist mà không cần đọc HTTP bytes.
   - Sử dụng build tag `//go:build !linux`.
3. **eBPF Linux Driver (`internal/shield/ebpf_linux.go` & `ebpf/xdp_filter.c` - Phục vụ Production Linux):**
   - Viết hook `XDP` (eXpress Data Path) bằng C.
   - **Parser:** Parse chuẩn Ethernet header, IPv4 header, TCP/UDP header.
   - **SYN Flood Prevention:** Đếm số lượng cờ `SYN` từ mỗi IP (Tracking bằng BPF Map). Nếu vượt ngưỡng -> return `XDP_DROP`.
   - Sử dụng thư viện `cilium/ebpf` để load cục compiled object `.o` vào Linux Kernel qua Golang.
   - Đồng bộ danh sách cấm từ Go (`Block(ip)`) xuống thẳng Kernel qua BPF Map.
   - Sử dụng build tag `//go:build linux`.

---

## Phase 3: Intelligence & Security Modules (Trí tuệ Nhân tạo & Bảo mật)
**Mục tiêu:** Lắp não cho Proxy (Framework) để nó nhận diện các cuộc tấn công tinh vi nhắm vào layer 7 (HTTP Flood, Slowloris) và tự động cập nhật eBPF Blocklist.

**Chi tiết công việc (Tasks):**
1. **Redis Rate Limiter (`internal/ratelimit/limiter.go`):**
   - Setup kết nối Redis với tính năng Fail-Open.
   - Implement **Sliding Window Counter** bằng Lua Script trên Redis (mượt mà và tránh lag do gửi quá nhiều command).
   - Tính năng **Subnet Aggregation**: Gom nhóm theo dải `/24` nếu có hiện tượng xoay IP tấn công.
2. **IP Blocklist Manager (`internal/blocklist/blocklist.go`):**
   - Xây dựng module quản lý IP bị cấm với TTL (Time-To-Live, VD: tự xả sau 24h).
   - Tự động gọi API của Loader eBPF ở Phase 2 để chặn luôn dưới Kernel những IP bị blocklist này.
   - Tích hợp gọi ngoài (async) đến API của AbuseIPDB chặn đánh giá uy tín IP.
3. **Anomaly Z-Score Detector (`internal/anomaly/detector.go`):**
   - Tracking chỉ số RPS (Request Per Second) cục bộ theo từng giây.
   - Tính Độ lệch chuẩn (Standard Deviation - Z-Score) dựa trên lịch sử baseline. Nếu RPS vọt lên bất thường -> Trigger hàm callback báo động hệ thống.
4. **Tích hợp Pipeline:** Gắn cả 3 module trên vào `proxy/pipeline.go` theo đúng trật tự: `Blocklist -> Rate Limit -> Anomaly Detect`.

---

## Phase 4: Telemetry & Realtime Observability (Nền tảng dữ liệu báo cáo)
**Mục tiêu:** Trích xuất dòng chảy dữ liệu hệ thống ra bên ngoài theo thời gian thực để chuẩn bị cho giao diện Dashboard đẹp mắt.

**Chi tiết công việc (Tasks):**
1. **Metrics Aggregator:**
   - Golang loop tính toán chỉ số nội bộ (Blocked counts, Passed counts, eBPF drop counts lấy từ Kernel BPF Map).
2. **WebSocket Hub (`internal/websocket/hub.go`):**
   - Setup `gorilla/websocket` server trên một port riêng (VD: 9090) tách biệt với Proxy port.
   - Xây dựng Pub/Sub hub, cứ **đúng 1 giây 1 lần** sẽ đóng gói chuẩn định dạng JSON các metric và `Broadcast` xuống toàn bộ client đang kết nối.
3. **Prometheus Exporter (`internal/metrics/prometheus.go`):**
   - Cắm Prometheus registry, tạo endpoint `/metrics` trên port 2112 để cho phép hệ thống devops (VD: Grafana) scrape dữ liệu định kỳ.

---

## Phase 5: The Web Dashboard Realtime (Trạm kiểm soát)
**Mục tiêu:** Một ứng dụng giao diện web độc lập tĩnh, ngầu, dark theme, theo dõi từng xung nhịp traffic.

**Chi tiết công việc (Tasks):**
1. **Khởi tạo Vite + React + TS:**
   - Cài đặt `shadcn/ui` và `tailwindcss` chuẩn bị giao diện "glassmorphism".
   - Setup layout màn hình (Header trạng thái, Card metrics, Biểu đồ giữa, Log/Danh sách cấm ở dưới).
2. **Connection Hooks (`hooks/useWebSocket.ts` & `useMetrics.ts`):**
   - Xử lý mượt mà việc kết nối WebSocket, tự động Reconnect theo cấp số nhân thời gian (Exponential Backoff) nếu timeout/đứt mạng.
   - Lưu trữ state bằng `Zustand`.
3. **Biểu đồ thời gian thực (`TrafficChart.tsx`):**
   - Render `Recharts` theo chuỗi thời gian, 2 đường line sinh động: Màu xanh cho Clean Traffic, Đỏ cho Blocked. Cập nhật mượt mà khi nhận feed từ WS mỗi giây.
4. **Quản lý hành động:**
   - Xây dựng màn hình/bảng tĩnh list IP, gọi HTTP API (đã thiết lập trong Go) để Unblock hoặc Manual Block.

---

## Phase 6: Operational & CLI (Kiểm thử, Đóng gói, Điều khiển)
**Mục tiêu:** Sẵn sàng đem lên Production với khả năng quản lý từ Command Line mạnh mẽ.

**Chi tiết công việc (Tasks):**
1. **NoxCtl CLI Component (`cmd/noxctl`):**
   - Build Tool bằng Golang thuần (`cobra` hoặc `bubbletea` UI đơn giản) để gọi UNIX socket nội bộ.
   - Các lệnh: `noxctl block <ip>`, `noxctl unblock <ip>`, `noxctl status`.
2. **Dockerization:**
   - Viết `docker-compose.yml` định nghĩa Redis container + Cấu hình Network Host cho phép cài cắm eBPF.
   - Cung cấp hướng dẫn Setup Production nhanh cho HĐH Linux Server (Ubuntu 22.04+).
3. **Stress Testing:**
   - Dùng script chạy `hey`, `wrk` hoặc `vegeta` tấn công vào chính Noxis để tinh chỉnh lại thuật toán Z-score và giới hạn RAM của fasthttp worker pool.
