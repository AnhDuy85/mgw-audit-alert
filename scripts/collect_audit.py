#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
collect_audit.py — Kéo audit log từ MGW appliance về máy local (PC/AWX EE)
qua SSH/SCP, để mgw_audit_monitor.py parse.

Cách hoạt động:
  - Dùng `scp` (hoặc `ssh cat`) lấy /opt/mwg/log/audit/audit*.log về thư mục
    đích (mặc định ../sample_logs).
  - Xác thực bằng SSH key (khuyến nghị) hoặc password (qua sshpass nếu có).

Chạy:
  python collect_audit.py --host DC-INT-MGW5500F-01 --user root \
      --key ~/.ssh/id_rsa --dest ../sample_logs
  # hoặc chỉ 1 số file gần đây:
  python collect_audit.py --host ... --user root --pattern 'audit2609*.log'

Python stdlib only (gọi scp/ssh của hệ thống qua subprocess).
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def run(cmd):
    print("+ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True)


def collect_scp(host, user, remote_dir, pattern, dest, key, port, use_sshpass, password):
    """Dùng scp kéo file khớp pattern về dest."""
    Path(dest).mkdir(parents=True, exist_ok=True)
    remote = f"{user}@{host}:{remote_dir}/{pattern}"

    base = []
    if use_sshpass and password:
        base = ["sshpass", "-p", password]

    scp = base + ["scp", "-P", str(port), "-o", "StrictHostKeyChecking=no"]
    if key:
        scp += ["-i", os.path.expanduser(key)]
    scp += [remote, str(dest)]

    r = run(scp)
    if r.returncode != 0:
        print(r.stderr.strip())
        return False, r.stderr.strip()
    return True, ""


def collect_ssh_cat(host, user, remote_dir, pattern, dest, key, port, use_sshpass, password):
    """
    Fallback: nếu scp glob không được, dùng ssh liệt kê file rồi cat từng file.
    An toàn khi appliance hạn chế scp.
    """
    Path(dest).mkdir(parents=True, exist_ok=True)
    base = []
    if use_sshpass and password:
        base = ["sshpass", "-p", password]

    ssh = base + ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no"]
    if key:
        ssh += ["-i", os.path.expanduser(key)]
    ssh_target = f"{user}@{host}"

    # Liệt kê file khớp pattern.
    ls = run(ssh + [ssh_target, f"ls -1 {remote_dir}/{pattern} 2>/dev/null"])
    if ls.returncode != 0 or not ls.stdout.strip():
        return False, "Không liệt kê được file audit qua ssh."

    files = [f.strip() for f in ls.stdout.splitlines() if f.strip()]
    ok = 0
    for rf in files:
        name = Path(rf).name
        out_path = Path(dest) / name
        cat = run(ssh + [ssh_target, f"cat {rf}"])
        if cat.returncode == 0:
            out_path.write_text(cat.stdout, encoding="utf-8")
            print(f"  -> {out_path} ({len(cat.stdout)} bytes)")
            ok += 1
    return ok > 0, f"Lấy {ok}/{len(files)} file."


def _ssh_base(key, port, use_sshpass, password):
    base = []
    if use_sshpass and password:
        base = ["sshpass", "-p", password]
    ssh = base + ["ssh", "-p", str(port), "-o", "StrictHostKeyChecking=no"]
    if key:
        ssh += ["-i", os.path.expanduser(key)]
    return ssh


def datetime_today():
    """Trả về ngày hôm nay dạng YYMMDD (khớp tên file audit MGW)."""
    from datetime import datetime
    return datetime.now().strftime("%y%m%d")


def _yymmdd_to_iso_prefix(yymmdd):
    """'260918' -> '2026-09-18' để so với event['date']."""
    if not yymmdd or len(yymmdd) != 6:
        return ""
    return f"20{yymmdd[0:2]}-{yymmdd[2:4]}-{yymmdd[4:6]}"


def load_secret():
    """Đọc config/secret.json (nếu có) -> dict mgw {host,user,password,port}.
    Không commit file này (gitignore). Env override: MGW_HOST/MGW_USER/MGW_SSH_PASSWORD."""
    sec_path = Path(__file__).resolve().parent.parent / "config" / "secret.json"
    data = {}
    if sec_path.exists():
        try:
            data = json.loads(sec_path.read_text(encoding="utf-8-sig")).get("mgw", {})
        except Exception as e:
            print(f"[secret.json] đọc lỗi: {e}")
            data = {}
    return {
        "host": os.environ.get("MGW_HOST") or data.get("host", ""),
        "user": os.environ.get("MGW_USER") or data.get("user", "root"),
        "password": os.environ.get("MGW_SSH_PASSWORD") or data.get("password", ""),
        "port": int(data.get("port", 22)),
    }


def _find_plink():
    """Tìm plink (PuTTY) để login bằng password không cần sshpass."""
    import shutil
    p = shutil.which("plink")
    if p:
        return p
    for cand in [r"C:\Program Files\PuTTY\plink.exe", r"C:\Program Files (x86)\PuTTY\plink.exe"]:
        if os.path.exists(cand):
            return cand
    return None


def fetch_audit_raw(host, user, remote_dir, pattern, key, port, use_sshpass, password, quiet=False):
    """SSH vào MGW, cat file audit khớp pattern, trả về (raw_text, rc)."""
    target = f"{user}@{host}"
    remote_cmd = f"cat {remote_dir}/{pattern} 2>/dev/null"

    plink = _find_plink()
    if password and plink:
        cmd = [plink, "-ssh", "-P", str(port), "-l", user, "-pw", password, host, remote_cmd]
        if not quiet:
            print(f"Đọc {remote_dir}/{pattern} từ {host} qua plink (auto-login)...")
    else:
        ssh = _ssh_base(key, port, use_sshpass, password)
        cmd = ssh + [target, remote_cmd]
        if not quiet:
            print(f"Đọc {remote_dir}/{pattern} từ {host} qua ssh...")

    # Capture stdout (nội dung log) + stderr (lỗi) riêng để chẩn đoán.
    stdin_input = "y\n" if (password and plink) else None
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          input=stdin_input, encoding="utf-8", errors="replace")
    raw = proc.stdout or ""
    if proc.returncode != 0 and not quiet:
        err = (proc.stderr or "").strip()
        if err:
            print("   [ssh/plink stderr]:", err[:500])
    return raw, proc.returncode


def _get_changes(raw, watch_actions, filter_date=""):
    """Parse raw + lọc watch_actions + khử DUPLICATE + (tuỳ chọn) lọc theo ngày."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import audit_parser as ap_mod
    events = ap_mod.parse_audit_text(raw)
    changes = [e for e in events if e.get("action") in watch_actions]

    iso_date = _yymmdd_to_iso_prefix(filter_date) if filter_date else ""
    if iso_date:
        changes = [e for e in changes if e.get("date") == iso_date]

    # KHỬ DUPLICATE ở 2 tầng:
    # (1) entries trong từng sự kiện: bỏ giá trị lặp (MODIFIED ghi cũ+mới trùng).
    # (2) sự kiện trùng nhau: cùng (timestamp,user,action,source,entries) -> giữ 1.
    seen_ev = set()
    deduped = []
    for e in changes:
        uniq_entries = list(dict.fromkeys(e.get("entries", [])))  # giữ thứ tự, bỏ trùng
        e["entries"] = uniq_entries
        key = (e.get("timestamp_raw", ""), e.get("user", ""), e.get("action", ""),
               e.get("source_name", ""), tuple(uniq_entries))
        if key in seen_ev:
            continue
        seen_ev.add(key)
        deduped.append(e)

    return deduped, iso_date


def show_direct(host, user, remote_dir, pattern, key, port, use_sshpass, password, watch_actions, filter_date=""):
    """Đọc audit log trực tiếp qua SSH và HIỂN THỊ thay đổi ra màn hình."""
    raw, rc = fetch_audit_raw(host, user, remote_dir, pattern, key, port, use_sshpass, password)
    if rc != 0 or not raw.strip():
        print("❌ Không đọc được audit log (rc=%d). Kiểm tra host(IP)/user/password/mạng." % rc)
        return 1

    changes, iso_date = _get_changes(raw, watch_actions, filter_date)

    title_date = f"   |   NGÀY {iso_date}" if iso_date else ""
    print("=" * 78)
    print(f" AUDIT MGW — {host}{title_date}   |   {len(changes)} thay đổi cấu hình")
    print("=" * 78)
    print(f"{'THỜI GIAN':<21}{'USER':<20}{'ACTION':<18}ĐỐI TƯỢNG")
    print("-" * 78)
    for e in changes:
        ts = f"{e.get('date','')} {e.get('time','')}".strip()
        print(f"{ts:<21}{e.get('user','?'):<20}{e.get('action','?'):<18}{e.get('source_name','') or e.get('source_type','')}")
        if e.get("entries"):
            preview = ", ".join(e["entries"][:5])
            more = f" (+{len(e['entries'])-5})" if len(e["entries"]) > 5 else ""
            print(f"{'':<59}↳ {preview}{more}")
    print("-" * 78)

    # Thống kê theo action.
    from collections import Counter
    cnt = Counter(e.get("action") for e in changes)
    if cnt:
        print(" Tổng theo action:", "  ".join(f"{a}={n}" for a, n in cnt.most_common()))
    return 0


def daily_alert(host, user, remote_dir, pattern, key, port, use_sshpass, password,
                watch_actions, filter_date, tg_token, tg_chat, seen_path,
                summary_threshold=12, dry_run=False):
    """
    MỤC TIÊU CHÍNH: đẩy cảnh báo Telegram các thay đổi audit THEO NGÀY.
      - SSH lấy audit log của ngày (filter_date).
      - Lọc watch_actions + đúng ngày.
      - Dedup theo seen_path (không gửi trùng nếu chạy lại nhiều lần trong ngày).
      - Gửi Telegram: mỗi thay đổi 1 tin; nếu > summary_threshold -> 1 tin tổng hợp.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import telegram_notify as tg
    import audit_parser as ap_mod

    raw, rc = fetch_audit_raw(host, user, remote_dir, pattern, key, port, use_sshpass, password, quiet=True)
    if rc != 0 or not raw.strip():
        print("❌ Không đọc được audit log (rc=%d)." % rc)
        if tg_token and tg_chat and not dry_run:
            tg._send_raw(tg_token, tg_chat, tg.build_alert_system(
                "MGW AUDIT - LỖI ĐỌC LOG",
                f"Không đọc được audit log từ {host} (rc={rc}). Kiểm tra kết nối/credential.",
                severity="critical"))
        return 1

    changes, iso_date = _get_changes(raw, watch_actions, filter_date)
    print(f"Ngày {iso_date or '(all)'}: {len(changes)} thay đổi cấu hình.")

    # Dedup.
    seen = set()
    sp = Path(seen_path)
    if sp.exists():
        try:
            seen = set(tuple(k) for k in json.loads(sp.read_text(encoding="utf-8")))
        except Exception:
            seen = set()
    new_seen = set(seen)
    to_alert = []
    for e in changes:
        k = ap_mod.dedup_key(e)
        if k in seen:
            continue
        new_seen.add(k)
        to_alert.append(e)

    print(f"Thay đổi MỚI cần cảnh báo: {len(to_alert)}")
    if not to_alert:
        return 0

    if dry_run:
        for e in to_alert:
            print("\n" + tg.build_alert_mgw(e))
        print("\n[DRY-RUN] không gửi Telegram, không lưu dedup.")
        return len(to_alert)

    sent = 0
    if len(to_alert) > summary_threshold:
        if tg._send_raw(tg_token, tg_chat, tg.build_alert_summary(to_alert, host)):
            sent += 1
    else:
        import time as _t
        for e in to_alert:
            if tg._send_raw(tg_token, tg_chat, tg.build_alert_mgw(e)):
                sent += 1
            _t.sleep(1.0)

    # Lưu dedup sau khi gửi.
    if sent > 0 or len(to_alert) > summary_threshold:
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(json.dumps([list(k) for k in list(new_seen)[-20000:]], ensure_ascii=False), encoding="utf-8")
    print(f"Đã gửi {sent} tin cảnh báo Telegram.")
    return sent


def load_telegram():
    """Đọc telegram {bot_token,chat_id} từ config/secret.json (nếu có)."""
    sec_path = Path(__file__).resolve().parent.parent / "config" / "secret.json"
    if sec_path.exists():
        try:
            return json.loads(sec_path.read_text(encoding="utf-8-sig")).get("telegram", {})
        except Exception:
            pass
    return {}


def main():
    _sec = load_secret()
    _sec_tg = load_telegram()
    ap = argparse.ArgumentParser(description="Collect / xem trực tiếp MGW audit log qua SSH")
    ap.add_argument("--host", default=_sec["host"] or None,
                    help="MGW IP (mặc định lấy từ config/secret.json hoặc env MGW_HOST)")
    ap.add_argument("--user", default=_sec["user"],
                    help="SSH user (mặc định từ secret.json hoặc root)")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--remote-dir", default="/opt/mwg/log/audit")
    ap.add_argument("--pattern", default="audit*.log", help="Glob file cần lấy")
    ap.add_argument("--dest", default="../sample_logs", help="Thư mục lưu local")
    ap.add_argument("--key", default="", help="Đường dẫn SSH private key")
    ap.add_argument("--sshpass", action="store_true", help="Dùng sshpass + password (env MGW_SSH_PASSWORD)")
    ap.add_argument("--method", choices=["scp", "sshcat"], default="scp")
    ap.add_argument("--show", action="store_true",
                    help="Đọc TRỰC TIẾP qua SSH và hiển thị thay đổi ngay (không lưu file)")
    ap.add_argument("--today", action="store_true",
                    help="Chỉ lấy dữ liệu HÔM NAY (file auditYYMMDD0000.log + audit.log đang ghi)")
    ap.add_argument("--date", default="",
                    help="Lấy theo ngày cụ thể YYMMDD (vd 260918). Bỏ qua nếu dùng --today")
    ap.add_argument("--alert", action="store_true",
                    help="Gửi cảnh báo Telegram thay đổi audit (dedup)")
    ap.add_argument("--dry-run", action="store_true", help="Với --alert: in ra thay vì gửi Telegram")
    ap.add_argument("--loop", action="store_true",
                    help="Chạy LIÊN TỤC: quét mỗi --interval giây, có thay đổi MỚI -> alert NGAY")
    ap.add_argument("--interval", type=int, default=60,
                    help="Chu kỳ quét khi --loop (giây, mặc định 60)")
    ap.add_argument("--all-days", action="store_true",
                    help="Với --alert: theo dõi TẤT CẢ (không giới hạn ngày) - phát hiện thay đổi mới bất kỳ")
    args = ap.parse_args()

    # Với --today/--date: LẤY TẤT CẢ audit*.log (glob '*' bền vững trên mọi sh,
    # không dùng brace expansion), rồi LỌC THEO NGÀY ở tầng Python (_get_changes).
    # Tránh phụ thuộc tên file chính xác / file ngày chưa tồn tại.
    # (Giữ nguyên args.pattern = audit*.log mặc định.)

    # Password: ưu tiên secret.json/env (để plink auto-login), fallback sshpass.
    password = _sec["password"] or (os.environ.get("MGW_SSH_PASSWORD", "") if args.sshpass else "")

    if not args.host:
        print("❌ Chưa có host. Điền IP MGW vào config/secret.json (mgw.host) hoặc dùng --host <IP>.")
        return 1

    pattern = args.pattern  # audit*.log - lấy tất cả, lọc ngày ở Python
    watch = ["ADDED_CONTENT", "DELETED_CONTENT", "MODIFIED_CONTENT", "MODIFIED_RULE"]
    # --all-days: không giới hạn ngày (theo dõi mọi thay đổi mới bất kỳ).
    # Ngược lại: mặc định theo dõi HÔM NAY (đúng "thay đổi trong ngày").
    if args.all_days:
        filter_date = ""
    else:
        filter_date = args.date or datetime_today()

    if args.alert:
        tg_token = os.environ.get("TELEGRAM_BOT_TOKEN") or _sec_tg.get("bot_token", "")
        tg_chat = os.environ.get("TELEGRAM_CHAT_ID") or _sec_tg.get("chat_id", "")
        if not args.dry_run and (not tg_token or not tg_chat):
            print("❌ Thiếu Telegram token/chat_id. Đặt env TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID "
                  "hoặc telegram trong secret.json.")
            return 1

        def _one_pass():
            # seen theo NGÀY (hoặc 'all') -> dedup, chạy lại không gửi trùng.
            fd = "" if args.all_days else (args.date or datetime_today())
            seen_path = str(Path(__file__).resolve().parent.parent / "logs" /
                            f"seen_{fd or 'all'}.json")
            return daily_alert(args.host, args.user, args.remote_dir, pattern, args.key,
                               args.port, args.sshpass, password, watch, fd,
                               tg_token, tg_chat, seen_path, dry_run=args.dry_run)

        # LOOP: quét liên tục, có thay đổi MỚI -> alert NGAY.
        if args.loop:
            import time as _t
            print(f"🔁 LOOP MODE: quét mỗi {args.interval}s. Thay đổi mới -> alert ngay. (Ctrl+C để dừng)")
            while True:
                try:
                    _one_pass()
                except KeyboardInterrupt:
                    print("\nDừng loop.")
                    break
                except Exception as e:
                    print(f"[loop] lỗi (bỏ qua vòng này): {e}")
                _t.sleep(args.interval)
            return 0

        return _one_pass()

    # Chế độ xem trực tiếp: SSH -> parse -> in màn hình, không lưu file.
    if args.show:
        return show_direct(args.host, args.user, args.remote_dir, pattern,
                           args.key, args.port, args.sshpass, password, watch,
                           filter_date=filter_date)

    if args.method == "scp":
        ok, msg = collect_scp(args.host, args.user, args.remote_dir, args.pattern,
                              args.dest, args.key, args.port, args.sshpass, password)
        if not ok:
            print("scp thất bại, thử fallback ssh cat...")
            ok, msg = collect_ssh_cat(args.host, args.user, args.remote_dir, args.pattern,
                                      args.dest, args.key, args.port, args.sshpass, password)
    else:
        ok, msg = collect_ssh_cat(args.host, args.user, args.remote_dir, args.pattern,
                                  args.dest, args.key, args.port, args.sshpass, password)

    if ok:
        files = sorted(Path(args.dest).glob(args.pattern))
        print(f"\n✅ Đã collect {len(files)} file audit về {args.dest}:")
        for f in files:
            print(f"   {f.name}  ({f.stat().st_size} bytes)")
        print("\nBước tiếp: python collect_audit.py --alert --today --dry-run")
        return 0
    else:
        print(f"\n❌ Collect thất bại: {msg}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
