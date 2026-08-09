# 🔑 Key Manager — LQ Mod

Web quản lý key cho iOS mod, deploy lên **GitHub Pages** (giao diện admin) + **Cloudflare Workers** (API validate thật).

---

## 📁 Cấu trúc

```
key-manager-web/
├── index.html              ← Giao diện admin (GitHub Pages)
├── cloudflare-worker.js    ← API validate (Cloudflare Workers)
└── README.md
```

---

## 🚀 Deploy bước 1 — GitHub Pages (Giao diện Admin)

1. Tạo GitHub repo mới (ví dụ: `key-manager`)
2. Upload toàn bộ folder này vào repo
3. Vào **Settings → Pages → Source**: chọn `main` branch
4. Truy cập: `https://YOUR_USERNAME.github.io/key-manager/`

**Đăng nhập mặc định:**
- Username: `admin`
- Password: `lqmod@2026` ← **ĐỔI NGAY** trong file `index.html` dòng `adminPass`

---

## ⚡ Deploy bước 2 — Cloudflare Workers (API thật)

### Setup Cloudflare Worker:

1. Đăng ký tài khoản [Cloudflare](https://cloudflare.com) (miễn phí)
2. Vào **Workers & Pages → Create Worker**
3. Paste nội dung `cloudflare-worker.js` vào editor
4. Tạo **KV Namespace** tên `KEYS_KV`:
   - Workers → KV → Create namespace
5. Bind KV vào Worker:
   - Worker Settings → Variables → KV Namespace Bindings
   - Variable name: `KEYS_KV`
6. Thêm **Environment Variable**:
   - `ADMIN_TOKEN` = `your-secret-admin-token-here`
7. **Save & Deploy**

### URL Worker của bạn sẽ là:
```
https://your-worker.YOUR_NAME.workers.dev
```

---

## 🔧 Kết nối iOS app với API

Trong file `KeyAuth/KeyAuthManager.h`, sửa dòng:
```objc
#define KEY_AUTH_API_BASE @"https://YOUR_USERNAME.github.io/YOUR_REPO"
```
thành URL Cloudflare Worker của bạn:
```objc
#define KEY_AUTH_API_BASE @"https://your-worker.your-name.workers.dev"
```

---

## 📲 Luồng hoạt động

```
App khởi động
    └─► Hiện KeyLoginViewController (toàn màn hình, không tắt được)
            └─► Nếu có key lưu → tự động validate
            └─► Nếu không → đếm ngược 30s → nếu không nhập → exit(0)
    └─► Validate: GET /api/validate
            Headers: X-Auth-Key, X-Device-ID
            Response: {status, role, days_left}
    └─► Nếu valid → vào game, set role cho FloatingButton
    └─► Mỗi 5 phút → check lại key real-time
```

---

## 🔑 Quản lý key trong Web Admin

| Tính năng | Mô tả |
|-----------|-------|
| Tạo key 1 thiết bị | 1 device ID duy nhất |
| Tạo key nhiều thiết bị | Tùy chỉnh số lượng |
| Thời hạn | 7 ngày / 30 ngày / 1 năm / tùy chỉnh |
| Ban key | Key bị ban → app báo lỗi, phải nhập key mới |
| Xóa key | Key không tồn tại → app báo xóa |
| Gia hạn | Thêm ngày vào key hết hạn → dùng được tiếp |
| Xem thiết bị | Danh sách device ID + lần cuối đăng nhập |
| Export JSON | Xuất validate.json để upload thủ công |

---

## 🎮 Tính năng trong game

### FloatingButton
- Sau **10 giây** không chạm → tự mờ xuống **40%**
- Chạm lại → về 100% ngay

### Admin vs Member
| Quyền | Member | Admin |
|-------|--------|-------|
| Dùng menu bình thường | ✅ | ✅ |
| Ẩn FloatingButton | ❌ | ✅ (2 ngón 2 lần) |

### Kiểm tra key real-time
- Mỗi **5 phút** → tự động check
- Key hết hạn / bị ban / bị xóa → hiện popup yêu cầu nhập key mới

---

## 🛡 Bảo mật

- Key sinh ngẫu nhiên format: `LQ-XXXXX-XXXXX-XXXXX-XXXXX`
- Device ID dùng `identifierForVendor` (không reset khi xóa app nếu cùng bundle group)
- Admin token Cloudflare không lộ ra client
- localStorage chỉ dùng cho giao diện admin (server-side là KV)
