# CC Gateway — Hướng dẫn Deploy & Sử dụng Local

Tài liệu tiếng Việt mô tả cách triển khai CC Gateway và cách dùng ở môi trường local. Bản tiếng Anh đầy đủ ở [`README.md`](README.md).

CC Gateway là một reverse proxy đứng giữa Claude Code và Anthropic API, làm nhiệm vụ chuẩn hoá identity (device ID, email, env, headers, prompt, billing header…) để nhiều máy có thể dùng chung một subscription mà chỉ "lộ" ra một danh tính duy nhất.

---

## 1. Yêu cầu

- **Node.js 22+** (chạy trực tiếp) hoặc **Docker + Docker Compose** (chạy container).
- Đã đăng nhập Claude Code trên máy admin ít nhất một lần (để có OAuth credentials trong macOS Keychain hoặc `~/.claude/.credentials.json`).
- `python3`, `openssl`, `bash` (script setup cần đến).
- Tuỳ chọn: HTTP/HTTPS proxy (Clash, V2Ray…) nếu mạng cần.

Kiểm tra nhanh:

```bash
node -v          # >= v22
docker -v        # nếu định deploy bằng Docker
claude --version # đảm bảo đã login Claude Code
```

---

## 2. Chạy local (development)

### 2.1. Setup một câu lệnh

```bash
git clone https://github.com/motiful/cc-gateway.git
cd cc-gateway
npm install
bash scripts/quick-setup.sh
```

Script `quick-setup.sh` sẽ:

1. Đọc OAuth token (access + refresh + expires) từ Keychain hoặc `~/.claude/.credentials.json`.
2. Sinh `device_id` và `client_token` ngẫu nhiên.
3. Ghi `config.yaml` ở thư mục gốc.
4. Tạo launcher cho client đầu tiên ở `./clients/cc-<hostname>`.
5. Khởi động gateway ở `http://localhost:8443` bằng `npm run dev` (tsx watch, auto-reload).

Nếu `config.yaml` đã tồn tại, script chỉ start gateway, không ghi đè config.

### 2.2. Sử dụng

Mở terminal khác:

```bash
./clients/cc-<hostname>
```

Claude Code sẽ chạy và toàn bộ traffic đi qua gateway. Mọi tham số gốc của `claude` đều dùng được, ví dụ:

```bash
./clients/cc-<hostname> --print "hello"
./clients/cc-<hostname> --resume
```

### 2.3. Cài làm lệnh `ccg` cho tiện

```bash
chmod +x ./clients/cc-<hostname>
./clients/cc-<hostname> install   # tạo lệnh `ccg` toàn hệ thống
ccg                               # chạy Claude Code qua gateway
ccg status                        # xem trạng thái kết nối + hijack
ccg help                          # liệt kê toàn bộ subcommand
```

Tuỳ chọn "hijack" để lệnh `claude` mặc định cũng đi qua gateway:

```bash
ccg hijack    # alias claude → ccg (terminal mới tự áp dụng)
ccg release   # huỷ hijack, trả lại claude gốc
ccg native    # chạy claude gốc một lần, bỏ qua gateway
```

### 2.4. Thêm client (cho user khác trong team)

Có hai cách: dùng dashboard web (mục 4) hoặc dùng script:

```bash
bash scripts/add-client.sh alice
bash scripts/add-client.sh bob
```

Script sẽ:
- Sinh token mới và append vào `config.yaml` (gateway hot-reload trong ~2 giây nhờ `watchFile`).
- Tạo file `./clients/cc-alice`, `./clients/cc-bob`.

Gửi nguyên file launcher cho user — không cần share `config.yaml`, không cần OAuth login lại.

Mặc định launcher trỏ về `http://localhost:8443`. Để trỏ tới gateway từ xa:

```bash
bash scripts/add-client.sh alice "" gateway.example.com:8443 https
```

Bốn tham số: `<tên> [token] [host:port] [scheme]`. Token để rỗng (`""`) sẽ tự sinh.

### 2.5. Chạy sau lưng proxy

```bash
HTTPS_PROXY=http://127.0.0.1:7890 bash scripts/quick-setup.sh
# hoặc chạy thủ công:
HTTPS_PROXY=http://127.0.0.1:7890 npm run dev
```

Gateway tôn trọng `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` cho cả request lên Anthropic API lẫn refresh token.

### 2.6. Lệnh npm hữu ích

```bash
npm run dev                      # tsx watch, auto-reload
npm run build                    # biên dịch TypeScript ra dist/
npm start                        # chạy bản đã build
npm test                         # chạy test rewriter
npm run add-user -- <username>   # tạo user đăng nhập dashboard (bản đã build)
npm run add-user:dev -- <username>  # tương tự, chạy bằng tsx
npm run generate-token           # sinh token rời
npm run generate-identity        # sinh identity rời
```

> **Lưu ý:** `add-user` tạo tài khoản đăng nhập **dashboard web** (lưu trong SQLite ở `./data/ccg.db`), khác với `add-client.sh` (tạo launcher Claude Code cho client). Xem chi tiết ở mục 4.

---

## 3. Deploy bằng Docker (production)

### 3.1. Setup tự động

Trên máy admin (đã login Claude Code):

```bash
bash scripts/admin-setup.sh
```

Script sẽ hỏi tương tác:
1. Lấy OAuth credentials.
2. Tạo `config.yaml` + launcher cho client đầu tiên.
3. Build và `docker compose up -d`.
4. Hỏi địa chỉ public mà client sẽ kết nối tới.

Sau khi container chạy, kiểm tra:

```bash
docker compose ps
docker compose logs -f gateway
curl http://localhost:8443/_health   # phải trả về 200
```

### 3.2. Thêm client sau khi đã deploy

```bash
bash scripts/add-client.sh charlie "" your-domain.com:443 https
docker compose restart        # nạp lại danh sách token
```

`docker-compose.yml` mount `ccg_data` (volume) để giữ `config.yaml` + SQLite giữa các lần restart, nên `device_id` và token sẽ không bị reset.

### 3.3. Deploy với Coolify (sẵn cấu hình)

`docker-compose.yml` đã có sẵn label cho Coolify + Traefik:
- Tạo service mới trên Coolify, point tới repo này.
- Set domain (Coolify tự sinh `SERVICE_FQDN_GATEWAY`).
- Traefik sẽ tự cấp Let's Encrypt cert và redirect HTTP → HTTPS.
- Mount `~/.claude/.credentials.json` ở host vào `/app/data/claude-credentials.json` (read-only) để container tự bootstrap config lần đầu.

### 3.4. Deploy thủ công với TLS tự ký

Khi cần TLS mà không có domain công khai:

```bash
mkdir certs
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 365 -nodes -subj "/CN=cc-gateway"
```

Bỏ comment phần `tls` trong `config.yaml`, sau đó sinh launcher với scheme `https`:

```bash
bash scripts/add-client.sh alice "" <gateway-ip>:8443 https
```

Launcher tự thêm `NODE_TLS_REJECT_UNAUTHORIZED=0` để chấp nhận self-signed cert.

### 3.5. Tailscale (lựa chọn nhẹ nhất)

Nếu mọi máy đều có Tailscale, chạy gateway trên một máy bất kỳ trong mesh — không cần TLS, không cần public IP, không cần forward port. Trỏ launcher tới hostname Tailscale (vd: `gateway.tailnet-xxx.ts.net:8443`).

### 3.6. Auto-bootstrap config khi khởi động

Khi container start lần đầu mà chưa có `config.yaml` ở `/app/data/config.yaml` (hoặc đường dẫn trong `CCG_CONFIG_PATH`), gateway sẽ tự sinh config từ một trong các nguồn sau:

- `CCG_REFRESH_TOKEN` env var (nếu set).
- File `claude-credentials.json` mount vào (mặc định `/app/data/claude-credentials.json`, read-only).

`docker-compose.yml` đã cấu hình mount sẵn `/root/.claude/.credentials.json` của host vào path này, nên trên server vừa cài Claude Code chỉ cần `docker compose up -d` là gateway tự bootstrap.

Ngoài ra:
- **Token rotation persist**: mỗi lần OAuth refresh, refresh token mới được ghi đè vào `config.yaml` để restart không bị "replay" token đã tiêu thụ.
- **Sync from credentials**: nếu host chạy `claude` và rotate token, gateway phát hiện `refresh_token` trong `credentials.json` khác với `config.yaml` và đồng bộ lại trước khi load.

Có thể sinh thủ công `config.yaml` từ login Claude hiện có:

```bash
bash scripts/gen-config.sh --client whiletrue0x > config.yaml
# hoặc ghi thẳng vào file Coolify volume:
bash scripts/gen-config.sh --out /data/coolify/applications/<id>/config.yaml
```

---

## 4. Dashboard web

Gateway expose sẵn một dashboard quản trị ở chính port 8443 (`/dashboard`), không phải port riêng:

| Path | Mục đích |
|---|---|
| `/` | Redirect → `/dashboard` (nếu đã login) hoặc `/login` |
| `/login` | Form đăng nhập admin |
| `/dashboard` | Xem usage/cost + quản lý client |
| `/api/clients` | REST API list/create client (cookie session) |
| `/api/clients/<name>` | REST API delete client |
| `/_health` | Health check (không cần login) |

### 4.1. Tạo user đăng nhập dashboard

Lần đầu start, log sẽ cảnh báo `No dashboard users yet`. Tạo user:

```bash
# Local (dev)
npm run add-user:dev -- admin

# Trong container
docker compose exec gateway node dist/scripts/add-user.js admin
```

Script hỏi password tương tác (>= 8 ký tự), hash bằng scrypt, lưu vào SQLite (`./data/ccg.db` hoặc `config.db.path`). Sau đó truy cập `http://localhost:8443/login`.

### 4.2. Tính năng dashboard

- **Quản lý client trong UI**: thêm/xoá launcher trực tiếp, copy lệnh cài đặt cho user.
- **Per-request token usage & cost**: mỗi request lưu input / output / cache tokens riêng.
- **Tổng hợp theo period**: today / 7 ngày / 30 ngày / all time.
- **Hot-reload**: thêm/xoá client trong dashboard cập nhật `config.yaml` và gateway nạp lại token trong ~2 giây mà không cần restart.

Pricing tính trong `src/pricing.ts`. Dữ liệu metric lưu SQLite, sống cùng volume `ccg_data` nên không mất khi redeploy.

---

## 5. Cấu trúc file quan trọng

```
cc-gateway/
├── src/
│   ├── index.ts         # entrypoint, watchFile config hot-reload
│   ├── proxy.ts         # HTTP server, route dashboard + proxy upstream
│   ├── dashboard.ts     # HTML cho /login + /dashboard
│   ├── rewriter.ts      # rewrite identity, env, prompt, headers
│   ├── oauth.ts         # quản lý access/refresh token
│   ├── auth.ts          # auth bằng client token (proxy) + session (dashboard)
│   ├── users.ts         # CRUD user dashboard (scrypt hash)
│   ├── clients.ts       # CRUD client launcher
│   ├── db.ts            # SQLite (better-sqlite3)
│   ├── metrics.ts       # ghi nhận request + token usage
│   ├── usage-parser.ts  # bóc tách input/output/cache token từ response
│   ├── pricing.ts       # bảng giá theo model
│   ├── bootstrap-config.ts  # auto-sinh config.yaml lần đầu
│   ├── proxy-agent.ts   # honour HTTPS_PROXY / HTTP_PROXY
│   ├── session.ts       # cookie session cho dashboard
│   ├── config.ts        # parse YAML
│   ├── logger.ts
│   └── scripts/         # add-user, generate-token, generate-identity
├── scripts/             # bash scripts dùng từ shell
│   ├── quick-setup.sh   # setup + start local trong 1 lệnh
│   ├── admin-setup.sh   # deploy Docker tương tác
│   ├── add-client.sh    # thêm client + sinh launcher
│   ├── extract-token.sh # rút OAuth token khỏi Keychain
│   └── gen-config.sh    # sinh config.yaml từ login Claude hiện có
├── clients/             # launcher cho từng user (gitignore)
├── data/                # SQLite + config khi chạy local (gitignore)
├── config.yaml          # config gateway (gitignore, do script sinh hoặc bootstrap)
├── config.example.yaml  # mẫu để tham khảo cấu trúc
├── docker-compose.yml   # deploy Docker + Coolify + Traefik
├── Dockerfile           # multi-stage build Node 22
└── clash-rules.yaml     # rule Clash chặn traffic trực tiếp tới Anthropic
```

---

## 6. Troubleshooting

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| `Error: No Claude Code credentials found` | Chưa login Claude Code lần nào. Chạy `claude` trên máy admin, hoàn tất OAuth qua trình duyệt, rồi chạy lại setup. |
| `No dashboard users yet` ở log | Chạy `npm run add-user -- <username>` (hoặc `docker compose exec gateway node dist/scripts/add-user.js <username>`) để tạo user trước khi vào `/login`. |
| Gateway start xong nhưng client báo 401 | Token trong launcher không khớp `config.yaml`. Sinh lại launcher bằng `add-client.sh` với token đúng, hoặc kiểm tra mục `auth.tokens`. |
| Anthropic trả 401 dù vừa refresh | Đảm bảo bản đang chạy là sau commit `497f46f` (forward OAuth qua `Authorization: Bearer` + `anthropic-beta`). Build lại nếu deploy bằng Docker. |
| Refresh token bị "consumed" sau restart | Cần bản có `f22386e` — gateway tự ghi token rotated trở lại `config.yaml`. Kiểm tra quyền ghi của file/volume. |
| Refresh token hết hạn (hiếm, sau vài tháng) | Chạy lại `bash scripts/extract-token.sh` trên máy admin, hoặc cập nhật `oauth.refresh_token` trong `config.yaml`. |
| Request không qua proxy | Kiểm tra `HTTPS_PROXY` đã set khi start gateway chưa. Restart sau khi đổi env. |
| Docker container không đọc được credentials | Đảm bảo mount `~/.claude/.credentials.json:/app/data/claude-credentials.json:ro` đúng; với non-root user, chỉnh path host cho phù hợp. |
| Dashboard hiện 0 request dù client đang dùng | Kiểm tra `data/ccg.db` có quyền ghi; xem log `metrics`/`usage-parser` để bắt lỗi parse usage block. |
| MCP request không đi qua gateway | `mcp-proxy.anthropic.com` hard-code, không theo `ANTHROPIC_BASE_URL`. Dùng Clash chặn nếu không cần MCP. |

Log:
- Local: stdout của `npm run dev`.
- Docker: `docker compose logs -f gateway`.
- Health check: `GET /_health`.

---

Log:
- Local: stdout của `npm run dev`.
- Docker: `docker compose logs -f gateway`.
- Health check: `GET /_health`.

---

## 7. Các bước rút gọn

**Local, một mình, một máy:**
```bash
npm install && bash scripts/quick-setup.sh
npm run add-user:dev -- admin    # tạo user dashboard
./clients/cc-<hostname> install
ccg
# mở http://localhost:8443 để xem dashboard
```

**Server Docker, nhiều client:**
```bash
bash scripts/admin-setup.sh
docker compose exec gateway node dist/scripts/add-user.js admin
# Thêm client qua dashboard hoặc:
bash scripts/add-client.sh alice "" gateway.example.com:443 https
# gửi file ./clients/cc-alice cho Alice (config tự hot-reload, không cần restart)
```

Xem [`README.md`](README.md) để biết chi tiết về cơ chế rewrite, OAuth lifecycle, Clash rules và các caveat.
