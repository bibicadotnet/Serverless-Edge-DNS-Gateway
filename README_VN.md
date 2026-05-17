# 🛡️ Serverless Edge DNS Gateway
[English](README.md) | [Tiếng Việt](README_VN.md)

Dịch vụ DNS-over-HTTPS (DoH) bảo mật, hiệu năng cao, chạy trên hạ tầng Edge toàn cầu của Cloudflare Pages. Giải pháp tối ưu tốc độ truy cập, độ chính xác vị trí địa lý (ECS) và chặn quảng cáo chuyên nghiệp.

---

## ⚡ Tính năng nổi bật

*   **Mức độ sử dụng miễn phí**: chạy hoàn toàn trên gói Free của Cloudflare Pages với hạn mức 100,000 requests mỗi ngày. Với mức tiêu thụ trung bình 200 – 4000 requests/thiết bị/ngày, bạn có thể sử dụng khoảng 10-20 thiết bị trên cùng một tài khoản (thậm chí 100-200 thiết bị nếu dùng thông thường)
*   **Hỗ trợ Custom Domain**: Dễ dàng gắn tên miền riêng để có địa chỉ DNS ngắn gọn, chuyên nghiệp. Bạn có thể sử dụng nhiều tài khoản Cloudflare khác nhau để nhân bản hạn mức (x100k/tài khoản) mà vẫn dùng được tên miền tùy chỉnh.
*   **Chặn quảng cáo thông minh**: Tự động lọc quảng cáo tại Edge bằng các danh sách chuyên nghiệp (AdGuard, ABPVN, Bypass-VN...), được cập nhật tự động mỗi giờ.
*   **Tối ưu hóa vị trí địa lý (ECS - RFC 7871)**: Tự động chèn EDNS Client Subnet (IPv4 `/24`, IPv6 `/48`) để đảm bảo các CDN (như Akamai, CloudFront, Fastly, BunnyCDN, Gcore) điều hướng bạn đến máy chủ gần nhất.
*   **Độ tin cậy cao với hệ thống dự phòng**: 
    *   **Primary/Fallback**: Tự động chuyển sang máy chủ Cloudflare Gateway dự phòng nếu máy chủ chính gặp sự cố.
    *   **Geo-Bypass**: Tự động phát hiện kết quả bị chặn địa lý (loopback 127.0.0.1) và phân giải lại qua **Mullvad DNS**.
*   **Bộ lọc truy vấn sớm (Edge Filtering)**: Loại bỏ các truy vấn không cần thiết (`ANY`, `AAAA`, `PTR`, `HTTPS`) ngay tại Edge để tiết kiệm tài nguyên và tăng tốc độ phản hồi.
*   **Lớp bảo vệ TLD nội bộ**: Ngăn rò rỉ các domain nội bộ (như `.local`, `.lan`, trang quản trị router) ra môi trường internet bằng cách trả về `NXDOMAIN` ngay lập tức.
*   **Điều hướng DNS (CNAME Injection)**: Công cụ ép định tuyến domain A sang domain B bằng bản ghi CNAME. Giúp tùy chỉnh chính xác cụm máy chủ CDN mong muốn (Bilibili, TikTok, Medium...).
*   **Cài đặt không cần App**: Hỗ trợ tạo file `.mobileconfig` chính chủ cho Apple và tích hợp trang Landing Page trực quan.

---

## 🚀 Hướng dẫn triển khai

### 1. Fork dự án & Bật Actions
1. [Fork dự án này](../../fork) về tài khoản GitHub của bạn.
2. Truy cập tab **Actions** trong repository bạn vừa fork và nhấn **I understand my workflows, go ahead and enable them**.
3. Chọn và **Enable** thủ công 2 workflows: `Update DNS Blocklists` và `Delete old workflow runs`.

### 2. Triển khai lên Cloudflare Pages
1. Vào [Workers & Pages > Create application > Connect to Git](https://dash.cloudflare.com/?to=/:account/pages/new/provider/github).
2. Chọn repository bạn vừa Fork.
3. **Build Settings**: Để **mặc định hoàn toàn** (không cần điền hay chỉnh sửa gì).
4. Nhấn **Save and Deploy**.

---

## ⚙️ Cấu hình (`functions/[[path]].js`)

Các cài đặt chi tiết nằm ở phần đầu của file [functions/[[path]].js](functions/[[path]].js#L2-L30).

### Hệ thống phân giải (Resolvers)
Các thông số dưới đây đã được cấu hình tối ưu sẵn theo mặc định.

> [!IMPORTANT]
> Chỉ duy nhất **Cloudflare Gateway** mới đảm bảo trả về kết quả CDN chính xác nhất cho các dịch vụ như Akamai. Bạn có thể sử dụng UPSTREAM mặc định có sẵn, hoặc tự tạo [DNS locations](https://dash.cloudflare.com/?to=/:account/one/networks/resolvers-proxies) riêng trong tài khoản Cloudflare của mình.

| Hằng số | Mặc định | Mô tả |
| :--- | :--- | :--- |
| `UPSTREAM_PRIMARY` | Cloudflare Gateway | URL máy chủ phân giải chính. |
| `UPSTREAM_FALLBACK` | Cloudflare Gateway | Máy chủ phân giải dự phòng. |
| `UPSTREAM_GEO_BYPASS`| `dns.mullvad.net` | Dùng khi máy chủ chính trả về loopback (127.0.0.1). |

### Tối ưu hóa tại Edge
| Hằng số | Mặc định | Mô tả |
| :--- | :--- | :--- |
| `BLOCK_AAAA` | `false` | Chặn bản ghi IPv6 (buộc định tuyến qua IPv4). |
| `BLOCK_HTTPS` | `false` | Chặn truy vấn Type 65 (giúp tăng tốc độ phân giải). |
| `BLOCK_ANY` | `false` | Chặn các truy vấn ANY tiêu tốn tài nguyên. |
| `BLOCK_PTR` | `false` | Chặn truy vấn DNS ngược. |
| `BLOCK_PRIVATE_TLD` | `true` | Chặn các domain nội bộ hoặc router. |
| `ECS_INJECTION_ENABLED` | `true` | Bật ECS Injection (Cần thiết để trả về đúng CDN). |

---

## 🛠 Quản lý quy tắc (Rules)

Các quy tắc nằm trong thư mục `rules/`. Khi bạn thực hiện thay đổi và commit lên GitHub, Cloudflare Pages sẽ tự động đồng bộ và áp dụng cấu hình mới ngay lập tức.

Các quy tắc chi tiết:

*   **`blocklists.txt`** / **`allowlists.txt`**: Được cập nhật tự động mỗi giờ.
    *   **Cơ chế**: Nếu một domain nằm trong `allowlists.txt`, nó sẽ luôn được cho phép kể cả khi có tên trong `blocklists.txt` (giúp tránh việc chặn nhầm).
    *   **Cách cấu hình**: Thay đổi các URL trong lệnh `curl` bên trong file [update_lists.sh](update_lists.sh#L34-L43) để thêm hoặc bớt các nguồn chặn/mở chặn.
*   **`private_tlds.txt`**: Thêm các domain nội bộ hoặc URL router của riêng bạn vào đây.
*   **`redirect_rules.txt`**: Điều hướng domain bằng cơ chế CNAME Injection (Domain A -> CNAME -> Domain B). Giúp tùy chỉnh CDN chính xác theo ý muốn.
    *   **Định dạng**: `domain-nguon domain-dich`
    *   **Ví dụ**: `www.bilibili.tv www.bilibili.tv.w.cdngslb.com`
    *   **Hiệu quả**: Nếu `www.bilibili.tv` trả về ngẫu nhiên nhiều CDN (như GSLB hoặc Akamai), quy tắc này sẽ ép nó luôn sử dụng `www.bilibili.tv.w.cdngslb.com`.

---

## 📱 Hướng dẫn cài đặt

### Trình duyệt (Chrome / Edge / Firefox)
1.  Vào **Cài đặt** > **Quyền riêng tư và bảo mật** > **Bảo mật**.
2.  Bật **"Sử dụng DNS bảo mật"** và chọn **"Tùy chỉnh"**.
3.  Dán URL của bạn: `https://your-project.pages.dev/dns-query`

### Apple (iOS / macOS)
1.  Mở URL dự án của bạn bằng trình duyệt **Safari**.
2.  Nhấn **Download Apple Profile** và cài đặt trong phần **Cài đặt hệ thống**.

### Android (App Intra)
1.  Mở ứng dụng Intra > **Cấu hình URL máy chủ tùy chỉnh**.
2.  Dán URL `/dns-query` của bạn và bật kết nối.

---

## 🔎 API & Các Endpoint

| Endpoint | Mô tả |
| :--- | :--- |
| `/dns-query` | Endpoint để thực hiện truy vấn DoH. |
| `/debug` | Trả về JSON tóm tắt cấu hình, thống kê và số lượng rule đang nạp. |
| `/apple` | Tạo file cấu hình `.mobileconfig` cho các thiết bị Apple. |

---
