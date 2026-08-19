# Key Manager LQ Mod — Hướng dẫn bản mới nhất

Bộ file này là phiên bản mới nhất gồm:

- `cloudflare-worker-optimized-no-keylog.js` — Cloudflare Worker API
- `index-optimized-no-keylog.html` — giao diện web quản lý key

Phiên bản này giữ các logic quản lý key, chat, phân quyền Admin/Member và đã **xóa hoàn toàn phần log bàn phím**.

---

## 1. Những thay đổi quan trọng của bản mới

### 1.1. Chỉ có Admin gốc mới được quản lý tài khoản

Admin gốc được xác định bằng 2 Cloudflare Secret:

- `LEGACY_ADMIN_USERNAME`
- `LEGACY_ADMIN_PASSWORD`

Tài khoản khác đăng ký trên web luôn được tạo với role `member`.

Chỉ Admin gốc mới được:

- mở phần **Tài khoản**;
- cấp `Admin` cho tài khoản khác;
- hạ `Admin` xuống `Member`.

Admin thường không được gọi API quản lý tài khoản dù cố gửi request trực tiếp.

### 1.2. Hạ Admin xuống Member sẽ khóa phiên đang đăng nhập

Khi Admin gốc hạ một tài khoản Admin xuống Member:

- Worker lưu role mới trong KV;
- phiên đăng nhập tiếp theo của tài khoản đó sẽ bị từ chối;
- web kiểm tra `/api/auth/me` định kỳ mỗi 3 giây;
- khi click hoặc nhấn phím, web kiểm tra lại ngay;
- nếu role không còn là Admin, web xóa token và đưa tài khoản về màn hình đăng nhập.

Vì vậy tài khoản đang đứng ở trang quản lý key, đang mở modal hoặc đang thao tác cũng sẽ bị đưa về login sau lần kiểm tra quyền kế tiếp.

### 1.3. Giảm request để tránh Cloudflare KV limit

Bản mới đã giảm các polling chính:

| Chức năng | Bản trước | Bản mới |
|---|---:|---:|
| Tự refresh danh sách key | 15 giây | 3 phút |
| Chat unread/sidebar | khoảng 2 giây | 30 giây |
| Kiểm tra session Admin | rất thường xuyên | 3 giây |
| Cache `/api/admin/list` | Không | 3 phút |
| Cache `/api/admin/users` | Không | 3 phút |
| Cache chat unread | Không | 3 phút |
| Cache chat list | Không | 3 phút |

Worker dùng runtime cache để tránh gọi `KV.list()` lặp lại trong cùng Worker isolate.

### 1.4. Đã xóa hoàn toàn log bàn phím

Bản này không còn phần quản lý keyboard log trên web.

Đã loại bỏ:

- giao diện xem log bàn phím;
- modal log bàn phím;
- chức năng refresh/copy/xóa keyboard log;
- API dành riêng cho keyboard log;
- `KV.list()` của namespace `keylog:`.

Nếu một phiên bản game cũ vẫn gửi request tới endpoint keyboard log, request đó không còn được xử lý; endpoint xác thực key `/api/validate` vẫn hoạt động độc lập.

---

# 2. Chuẩn bị Cloudflare

## 2.1. Tạo KV Namespace

Trong Cloudflare Dashboard:

**Workers & Pages → KV → Create namespace**

Tạo một namespace, ví dụ:

`LQ_KEYS_KV`

Sau đó bind namespace này vào Worker với biến:

`KEYS_KV`

Tên binding phải đúng **`KEYS_KV`** vì source Worker sử dụng:

```js
env.KEYS_KV
```

## 2.2. Tạo các Secret

Vào:

**Workers & Pages → Worker → Settings → Variables and Secrets**

Tạo 3 Secret:

### `AUTH_SECRET`

Một chuỗi ngẫu nhiên dài, dùng để ký session.

Ví dụ:

```text
một-chuỗi-ngẫu-nhiên-rất-dài-và-khó-đoán
```

Không dùng ví dụ trên trong production; hãy tạo chuỗi riêng.

### `LEGACY_ADMIN_USERNAME`

Tên tài khoản Admin gốc.

Ví dụ:

```text
legacyadmin
```

### `LEGACY_ADMIN_PASSWORD`

Mật khẩu Admin gốc.

Ví dụ:

```text
MatKhauAdminRiengCuaBan
```

**Không ghi 3 giá trị này vào HTML hoặc GitHub public.**

---

# 3. Deploy Cloudflare Worker

Dùng file:

`cloudflare-worker-optimized-no-keylog.js`

## Cách 1 — Dashboard

Vào Worker → **Edit code**.

Thay toàn bộ code Worker hiện tại bằng nội dung của:

```text
cloudflare-worker-optimized-no-keylog.js
```

Sau đó **Deploy / Save and deploy**.

Kiểm tra lại:

- KV binding: `KEYS_KV`
- Secret: `AUTH_SECRET`
- Secret: `LEGACY_ADMIN_USERNAME`
- Secret: `LEGACY_ADMIN_PASSWORD`

## Cách 2 — Wrangler

Nếu dùng Wrangler, có thể dùng file Worker làm entry point và cấu hình binding KV trong `wrangler.toml`.

Ví dụ cấu trúc:

```toml
name = "lq-key-manager"
main = "cloudflare-worker-optimized-no-keylog.js"
compatibility_date = "2026-08-19"

[[kv_namespaces]]
binding = "KEYS_KV"
id = "YOUR_KV_NAMESPACE_ID"
```

Sau đó cấu hình Secret bằng Wrangler và deploy.

---

# 4. Đưa HTML lên GitHub Pages

Dùng file:

`index-optimized-no-keylog.html`

GitHub Pages thường tìm `index.html`, vì vậy đổi tên:

```text
index-optimized-no-keylog.html
```

thành:

```text
index.html
```

Cấu trúc repository tối thiểu:

```text
your-repository/
├── index.html
└── README.md
```

Push lên GitHub.

Sau đó vào:

**Repository → Settings → Pages**

Chọn:

- **Source:** Deploy from a branch
- **Branch:** `main`
- **Folder:** `/ (root)`

Save.

Sau khi GitHub Pages deploy xong, mở trang web và nhập Worker URL.

---

# 5. Đăng nhập Admin gốc lần đầu

Mở web GitHub Pages.

Nhập:

```text
Worker URL: https://TEN-WORKER-CUA-BAN.workers.dev
Username: giá trị LEGACY_ADMIN_USERNAME
Password: giá trị LEGACY_ADMIN_PASSWORD
```

Đăng nhập.

Admin gốc sẽ hiển thị badge:

```text
ROOT ADMIN
```

và nhìn thấy nút:

```text
Tài khoản
```

Admin thường sẽ không thấy nút này.

---

# 6. Tạo tài khoản Member

Người dùng có thể bấm:

**Tạo tài khoản**

Tài khoản mới luôn bắt đầu là:

```text
Member
```

Không còn `BOOTSTRAP_ADMIN_SECRET`.

Không thể tự đăng ký thành Admin bằng mã trên web.

Muốn trở thành Admin phải được **Admin gốc cấp quyền**.

---

# 7. Cấp / hạ Admin

Đăng nhập bằng Admin gốc.

Bấm:

**Tài khoản**

Trong danh sách:

- Member → **Cấp Admin**
- Admin → **Hạ Member**

API phía Worker vẫn kiểm tra quyền Admin gốc, vì vậy không thể chỉ sửa HTML để giả mạo quyền.

---

# 8. Điều quan trọng về Cloudflare KV limit

Bản này đã giảm request đáng kể nhưng **không thể làm cho Cloudflare KV có quota vô hạn**.

Đặc biệt, danh sách key `/api/admin/list` vẫn dùng:

```js
env.KEYS_KV.list({ prefix: 'key:' })
```

nhưng kết quả được cache tối đa 3 phút trong Worker isolate.

Nút **Làm mới** trên web dùng:

```text
/api/admin/list?fresh=1
```

và chủ động bỏ cache để lấy dữ liệu mới. Vì vậy không nên bấm **Làm mới** liên tục khi Cloudflare đang gần hết quota `list`.

Ngoài `/api/admin/list`, một số chức năng chat/account đặc biệt vẫn còn `KV.list()` ở backend nhưng các luồng polling chính đã được giảm tần suất và một số kết quả có cache.

---

# 9. Nếu web báo `Failed to fetch`

Kiểm tra theo thứ tự:

### A. Worker còn hoạt động không?

Mở Worker URL.

### B. HTML có nhập đúng Worker URL không?

Ví dụ:

```text
https://lq-key-manager.example.workers.dev
```

Không thêm dấu `/` cuối cũng được vì giao diện tự xử lý.

### C. Kiểm tra KV binding

Tên phải chính xác:

```text
KEYS_KV
```

### D. Kiểm tra Secret

Phải có:

```text
AUTH_SECRET
LEGACY_ADMIN_USERNAME
LEGACY_ADMIN_PASSWORD
```

### E. Kiểm tra Cloudflare KV quota

Nếu Cloudflare báo:

```text
KV list() / limit exceeded for the day
```

thì danh sách key trên web có thể lỗi trong khi:

- tạo key vẫn có thể thành công;
- `/api/validate` vẫn có thể đọc key;
- game vẫn có thể đăng nhập bằng key;
- key cũ vẫn có thể hoạt động.

Điều này xảy ra vì `PUT`, `GET` và `LIST` là các loại thao tác KV khác nhau.

---

# 10. Key tạo được nhưng không xuất hiện trên danh sách

Nếu tạo key thành công nhưng load danh sách lại báo `Failed to fetch`, **không nên vội xóa hoặc tạo lại key**.

Kiểm tra Cloudflare Logs trước.

Nếu lỗi là:

```text
KV list() / limit exceeded for the day
```

thì key có thể vẫn tồn tại trong KV và `/api/validate` vẫn đọc được bình thường.

Vấn đề chỉ nằm ở việc Worker không thể `list` namespace để dựng danh sách cho dashboard.

---

# 11. Cache và realtime

### Danh sách key

- Tự refresh: 3 phút.
- Cache Worker: 3 phút.
- Nút **Làm mới**: ép lấy dữ liệu mới.

### Quyền Admin/Member

- Kiểm tra nền: 3 giây.
- Click: kiểm tra ngay.
- Keydown: kiểm tra ngay.

### Chat unread

- Poll sidebar: 30 giây.
- Các luồng chat realtime riêng vẫn hoạt động theo cơ chế realtime của hệ thống.

---

# 12. Không đặt Secret vào HTML

Không sửa HTML thành kiểu:

```js
const ADMIN_PASSWORD = '...';
```

và không commit các giá trị Secret vào GitHub.

HTML chỉ gửi username/password người dùng nhập tới Worker; Worker mới kiểm tra với Secret.

---

# 13. Hai file dùng trong bản này

## `cloudflare-worker-optimized-no-keylog.js`

Chức năng chính:

- đăng ký / đăng nhập / session;
- Admin gốc;
- cấp / hạ Admin;
- tạo / ban / unban / xóa / gia hạn key;
- quản lý thiết bị;
- permissions theo thiết bị;
- chat;
- cache dashboard;
- heartbeat/online;
- xác thực key `/api/validate`;
- không còn keyboard log.

## `index-optimized-no-keylog.html`

Chức năng chính:

- giao diện đăng nhập;
- đăng ký Member;
- dashboard quản lý key;
- thống kê;
- tìm kiếm/lọc;
- quản lý thiết bị;
- chat;
- quản lý tài khoản chỉ dành cho Admin gốc;
- tự phát hiện tài khoản bị hạ xuống Member;
- giảm polling;
- không còn giao diện keyboard log.

---

# 14. Cài đặt nhanh nhất

```text
1. Tạo Cloudflare KV
2. Bind KV thành KEYS_KV
3. Tạo AUTH_SECRET
4. Tạo LEGACY_ADMIN_USERNAME
5. Tạo LEGACY_ADMIN_PASSWORD
6. Deploy cloudflare-worker-optimized-no-keylog.js
7. Đổi index-optimized-no-keylog.html → index.html
8. Upload index.html lên GitHub Pages
9. Mở web
10. Nhập Worker URL
11. Đăng nhập bằng LEGACY_ADMIN_USERNAME / LEGACY_ADMIN_PASSWORD
```

---

# 15. Lưu ý khi nâng cấp từ bản cũ

Nếu Worker cũ vẫn có các Secret sau thì không cần dùng nữa:

```text
BOOTSTRAP_ADMIN_SECRET
```

Bản mới không sử dụng mã này để tạo Admin.

Nếu đã có các tài khoản Admin cũ trong KV, Admin gốc có thể hạ chúng xuống Member từ giao diện **Tài khoản**.

Không cần xóa namespace KV khi nâng cấp Worker; dữ liệu key/user hiện có vẫn được Worker mới đọc theo cùng prefix/key format.
