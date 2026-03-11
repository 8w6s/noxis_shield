#!/bin/bash
# VPS .172 Deployment Script for Mango Shield Test Site

IP="103.77.246.172"
PASS=""
REMOTE_PATH="/opt/mango-shield/test-site"

# Kiểm tra xem sshpass đã được cài đặt chưa
if ! command -v sshpass &> /dev/null; then
    echo "📦 Đang cài đặt sshpass để tự động nhập mật khẩu..."
    sudo apt-get update && sudo apt-get install -y sshpass
fi

echo "📂 Đang tạo thư mục từ xa..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no root@$IP "mkdir -p $REMOTE_PATH"

echo "🔄 Đang dừng server cũ trên VPS..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no root@${IP} "
    PID=\$(lsof -t -i:8080)
    if [ ! -z \"\$PID\" ]; then
        echo \"Dừng process \$PID...\"
        kill -9 \$PID
    fi
"

echo "🚀 Đang tải binary lên VPS ${IP}..."
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no server_linux root@${IP}:${REMOTE_PATH}/server_linux

echo "▶️ Đang khởi động server mới..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no root@${IP} "
    chmod +x ${REMOTE_PATH}/server_linux
    
    nohup ${REMOTE_PATH}/server_linux > ${REMOTE_PATH}/server.log 2>&1 &
    
    echo \"Kiểm tra trạng thái...\"
    sleep 2
    ps aux | grep server_linux | grep -v grep
"

echo "✅ Hoàn tất! Đã cập nhật giao diện DStat Ultra."
echo "🔗 Truy cập ngay: http://${IP}:8080"
