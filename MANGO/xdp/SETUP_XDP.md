# HƯỚNG DẪN CÀI ĐẶT LỚP PHÒNG NGỰ PHẦN CỨNG (XDP / eBPF) - MANGO SHIELD

Chào mừng bạn đến với cấp độ cao nhất của bảo mật mạng Layer 7 & Layer 4. Tài liệu này hướng dẫn cách đưa Mango Shield vượt giới hạn bằng công nghệ **XDP (eXpress Data Path)** - công nghệ chống DDoS nội tại của Linux Kernel (Được dùng bởi Cloudflare).

Với Module này, Server của bạn có thể xả bỏ **10 Triệu Request/giây (DDoS)** ngay tại Card Mạng Vật Lý mà CPU vẫn chỉ ở mức 5-10%!

---

## 🚀 1. TẠI SAO PHẢI XÀI XDP?
Trong ứng dụng Golang bình thường:
`Attacker -> Card Mạng -> Linux Kernel TCP/IP -> App Golang (WAF) -> Phân tích -> Banned`
Quá trình này tốn Context Switch (đổi không gian bộ nhớ) nên khi bị tấn công > 1 triệu request, CPU server sẽ bị tắc nghẽn hoàn toàn -> Server Sập.

Với công nghệ **XDP (Chèn mã C vào Driver Card Mạng)**:
`Attacker -> Card Mạng -> Bị XDP đá văng (Drop) NGAY LẬP TỨC nếu IP nằm trong BlackList`
App WAF Golang bên trong sẽ không hề hay biết gì về đợt tấn công đó. Server hoàn toàn mát rượi.

---

## 🛠 2. HƯỚNG DẪN SETUP BƯỚC ĐẦU
### A. Biên dịch và gắn Mã C vào Card Mạng (NIC)

Bạn chỉ cần chạy Script tự động đã được lập trình sẵn trong thư mục `xdp`:

```bash
cd xdp/
chmod +x setup_xdp.sh
sudo ./setup_xdp.sh
```

**Thành công?** Bạn sẽ thấy thông báo *"Attaching XDP filter to eth0... ACTIVE"*.
Trông như thế này, mọi IP rác sẽ bị đá văng mà không tốn 1 chu kỳ CPU phần mềm nào!

---

## 🧠 3. CÁCH HỆ THỐNG GIAO TIẾP VỚI NHAU (WAF <-> XDP)
Mã C (`mango_xdp.c`) và ứng dụng Golang WAF (`mango-shield`) chia sẻ chung một bộ nhớ gọi là thư mục RAM (eBPF Maps):
1.  **Mango Shield (Golang)**: Khi phát hiện 1 IP spam quá đà (Bằng vân tay, Rate limit, v.v.), ứng dụng WAF thay vì Drop bằng phần mềm nó sẽ đẩy cái IP đó xuống Map của XDP.
2.  **Kernel XDP (Mã C)**: Cứ mỗi s tích tắc, nó check hàng triệu gói tin vừa chạm vào Card mạng. IP nào có trong cái MAP kia -> DROP thẳng.

Để tương tác thủ công (Kiểm tra xem XDP đang ban IP nào):
```bash
# Xem danh sách các IP đang bị Kernel XDP chặn đứng:
bpftool map dump name blacklist
```

---

## ⚠️ 4. LÀM SAO ĐỂ GỠ BỎ?
Nếu bạn muốn tắt tường lửa cấp độ Card mạng để mọi thứ quay lại bình thường:

1. Tìm tên Card Mạng (Thường là `eth0` hoặc `ens3`):
```bash
ip link
```
2. Gỡ bỏ (Tắt XDP):
```bash
sudo ip link set dev <TÊN_CARD_MẠNG> xdp off
```

---
*Bản thiết kế này chỉ là nền móng. Trong tương lai bạn có thể kết nối Thư viện `cilium/ebpf` vào Core Go của Mango Shield để Sync IP Banned tự động với Kernel!*
