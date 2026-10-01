# MGW Audit Alert — Cảnh báo thay đổi cấu hình Web Gateway

Giám sát **audit log** của McAfee/Trellix Web Gateway (MGW 5500F) và gửi **cảnh
báo Telegram** khi có thay đổi cấu hình: thêm/sửa/xóa content (list, whitelist)
và rule. Bỏ qua login/logout thông thường.

Nguồn: `/opt/mwg/log/audit/audit*.log` (block phân cách bằng dòng gạch dưới),
đọc **trực tiếp qua SSH** từ appliance MGW.

---

## 1. Các action được cảnh báo

| Action | Ý nghĩa | Icon |
|--------|---------|------|
| `ADDED_CONTENT` | Thêm entry vào list/whitelist | 🟢 |
| `MODIFIED_CONTENT` | Sửa nội dung | 🟡 |
| `MODIFIED_RULE` | Sửa rule | 🟠 |
| `DELETED_CONTENT` | Xóa entry | 🔴 |

Bỏ qua: `USER_LOGIN`, `USER_LOGOUT`.

---

## 2. Cấu trúc

```
mgw-audit-alert/
├── config/
│   ├── config.json         # audit_dir, watch_actions, interval (không nhạy cảm)
│   └── secret.json         # SSH + Telegram credential (GITIGNORE, không commit)
├── scripts/
│   ├── audit_parser.py     # parse block audit -> event dict
│   ├── telegram_notify.py  # build + gửi alert (stdlib)
│   ├── collect_audit.py    # ENTRY CHÍNH: SSH lấy log + xem/alert
│   └── mgw_audit_monitor.py# engine parse+dedup (dùng khi có log local)
└── logs/                   # seen_<ngày>.json (dedup), tự sinh
```

Toàn bộ **Python stdlib** — chạy được trên appliance/AWX EE không cần pip.

---

## 3. Cấu hình credential (`config/secret.json`)

File này **KHÔNG commit** (đã gitignore). Điền:
```json
{
  "mgw": {
    "host": "10.4.255.98",
    "user": "pci-dss",
    "password": "***",
    "port": 22
  },
  "telegram": {
    "bot_token": "123456:ABC...",
    "chat_id": "-1001234567890"
  }
}
```

> **Bảo mật:** dùng user **không phải root** (least privilege) — chỉ cần quyền
> ĐỌC `/opt/mwg/log/audit/`. Ví dụ `pci-dss` hoặc `admin` (thêm group `mwg`).
> Có thể override bằng env: `MGW_HOST`, `MGW_USER`, `MGW_SSH_PASSWORD`,
> `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (ưu tiên hơn secret.json).
>
> Máy Windows không có `sshpass` -> script tự dùng **plink (PuTTY)** để
> auto-login bằng password.

---

## 4. Cách chạy

Từ thư mục `scripts/`:

**Xem trực tiếp thay đổi (không gửi):**
```bash
python collect_audit.py --show            # tất cả
python collect_audit.py --show --today    # chỉ hôm nay
python collect_audit.py --show --date 260924
```

**Cảnh báo Telegram (dedup, không gửi trùng):**
```bash
python collect_audit.py --alert --today --dry-run   # xem trước, không gửi
python collect_audit.py --alert --today             # gửi thật
```

**Cảnh báo theo CỬA SỔ thời gian (khuyến nghị cho AWX định kỳ):**
```bash
python collect_audit.py --alert --window 10 --from-file <log>  # 10' gần nhất
```
Chỉ lấy thay đổi trong N phút gần nhất. **Không có thay đổi -> không alert.**
Đặt N = chu kỳ AWX Schedule (vd chạy mỗi 10' -> `--window 10`). Dùng cách này
thì không cần dedup persistent giữa các lần chạy.

**Cảnh báo NGAY khi có thay đổi (loop liên tục):**
```bash
python collect_audit.py --alert --loop --interval 30
```
Quét mỗi 30s, phát hiện thay đổi mới -> alert ngay (độ trễ ~30s).

Tùy chọn: `--all-days` (theo dõi mọi ngày), `--today` (chỉ hôm nay).

---

## 5. Cơ chế chống trùng (không duplicate)

3 tầng:
1. **Entries trong 1 sự kiện**: bỏ giá trị lặp (MODIFIED ghi cũ+mới trùng).
2. **Sự kiện trùng nhau**: cùng (timestamp+user+action+source+entries) -> giữ 1.
3. **Dedup gửi Telegram**: `logs/seen_<ngày>.json` — đã gửi thì không gửi lại.

Dedup theo **từng ngày** (file riêng mỗi ngày), sang ngày mới tự reset.
Nếu >12 thay đổi/lần -> gửi 1 tin tổng hợp thay vì spam.

---

## 6. Chạy tự động 24/7

**systemd (server Linux) — alert nhanh nhất:**
```
ExecStart=/usr/bin/python3 /path/scripts/collect_audit.py --alert --loop --interval 30
```

**cron (digest/định kỳ):**
```cron
*/1 * * * * cd /path/scripts && python3 collect_audit.py --alert --today
```

**AWX**: playbook self-contained kéo log qua SSH + gửi Telegram, credential từ
AWX Credential (Machine + Telegram), theo pattern các project FAZ.

---

## 7. An toàn

- Chỉ **đọc** audit log, không sửa gì trên appliance.
- User monitor KHÔNG cần root — chỉ quyền đọc log.
- Không commit credential: dùng `secret.json` (gitignore) hoặc env.
- Luôn `--dry-run` kiểm tra trước khi bật gửi thật.
