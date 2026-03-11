import http.server
import socketserver
import mimetypes
import os

PORT = 8080

# Danh sách mapping extension chuẩn chỉ cho dân hệ thống
noxis_extensions = {
    '.go': 'text/plain',
    '.c': 'text/plain',
    '.h': 'text/plain',
    '.yaml': 'text/plain',
    '.yml': 'text/plain',
    '.md': 'text/plain',
    '.noxis': 'text/plain',
    '.sum': 'text/plain',
    '.mod': 'text/plain',
    '.sh': 'text/plain',
    '.json': 'application/json', # Giữ JSON để AI đọc đúng cấu trúc
}

# Những file đặc biệt không có đuôi
special_files = {'Makefile', 'Dockerfile', 'LICENSE', '.gitignore', '.env'}

class NoxisHandler(http.server.SimpleHTTPRequestHandler):
    def guess_type(self, path):
        basename = os.path.basename(path)
        
        # Ưu tiên kiểm tra các file đặc biệt không đuôi trước
        if basename in special_files:
            return 'text/plain'
            
        # Kiểm tra theo extension
        for ext, content_type in noxis_extensions.items():
            if path.lower().endswith(ext):
                return content_type
                
        # Nếu là file lạ, cứ ép về text/plain luôn cho AI dễ bú data
        base, ext = os.path.splitext(path)
        if ext:
            return 'text/plain'
            
        return super().guess_type(path)

    # Thêm cái này để tránh lỗi cache khi bạn sửa code
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

# Dùng Allow Reuse Address để tránh lỗi "Address already in use" khi khởi động lại nhanh
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReusableTCPServer(("", PORT), NoxisHandler) as httpd:
    print(f"--- Sato IDE Server Core ---")
    print(f"🌍 Public Link: http://103.156.2.17:{PORT}")
    print(f"🏠 Local Link: http://localhost:{PORT}")
    print(f"🛡️  Project: noxis_shield")
    print(f"-----------------------------")
    httpd.serve_forever()