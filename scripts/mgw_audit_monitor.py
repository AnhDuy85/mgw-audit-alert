#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mgw_audit_monitor.py — Giám sát audit log McAfee/Trellix Web Gateway (MGW)
và gửi cảnh báo Telegram khi có THAY ĐỔI CẤU HÌNH (thêm/sửa/xóa content, rule).

Nguồn: /opt/mwg/log/audit/audit*.log (block phân cách bằng dòng gạch dưới).
Lọc: chỉ các action trong watch_actions (mặc định ADDED/DELETED/MODIFIED_CONTENT,
     MODIFIED_RULE). Bỏ qua USER_LOGIN/LOGOUT.
Dedup: theo (timestamp+user+action+source+entries), lưu logs/seen.json để không
       gửi trùng giữa các lần quét.

Chạy:
  python mgw_audit_monitor.py --config ../config/config.json            # 1 lần
  python mgw_audit_monitor.py --config ../config/config.json --loop     # lặp
  python mgw_audit_monitor.py --config ../config/config.json --test     # test Telegram
  python mgw_audit_monitor.py --config ../config/config.json --dry-run  # in ra, KHÔNG gửi

Python stdlib only.
"""

import os
import sys
import json
import glob
import time
import logging
import argparse
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import audit_parser as ap
import telegram_notify as tg

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("mgw-audit")


def load_config(path):
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    # Overlay secret local (không commit) nếu có.
    local = Path(path).with_name("config.local.json")
    if local.exists():
        loc = json.loads(local.read_text(encoding="utf-8"))
        for k, v in loc.items():
            if isinstance(v, dict):
                cfg.setdefault(k, {}).update(v)
            else:
                cfg[k] = v
    # Telegram từ env (ưu tiên) - tiện cho AWX credential.
    tgc = cfg.setdefault("telegram", {})
    tgc["bot_token"] = os.environ.get("TELEGRAM_BOT_TOKEN") or tgc.get("bot_token", "")
    tgc["chat_id"] = os.environ.get("TELEGRAM_CHAT_ID") or tgc.get("chat_id", "")
    return cfg


def _seen_path(cfg):
    p = cfg.get("seen_file") or str(_HERE.parent / "logs" / "seen.json")
    Path(p).parent.mkdir(parents=True, exist_ok=True)
    return p


def load_seen(cfg):
    p = _seen_path(cfg)
    if not Path(p).exists():
        return set()
    try:
        return set(tuple(k) for k in json.loads(Path(p).read_text(encoding="utf-8")))
    except Exception:
        return set()


def save_seen(cfg, seen):
    p = _seen_path(cfg)
    try:
        trimmed = list(seen)[-10000:]
        Path(p).write_text(json.dumps([list(k) for k in trimmed], ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        log.warning("Không ghi được seen: %s", e)


def collect_events(cfg):
    """Đọc + parse tất cả file audit khớp glob trong config."""
    audit_dir = cfg.get("audit_dir", "/opt/mwg/log/audit")
    pattern = cfg.get("audit_glob", "audit*.log")
    paths = sorted(glob.glob(str(Path(audit_dir) / pattern)))
    if not paths:
        raise FileNotFoundError(f"Không tìm thấy audit log: {audit_dir}/{pattern}")
    events = []
    for p in paths:
        try:
            events.extend(ap.parse_audit_file(p))
        except Exception as e:
            log.warning("Parse lỗi %s: %s", p, e)
    return events, paths


def run_once(cfg, dry_run=False):
    tgc = cfg["telegram"]
    watch = set(cfg.get("watch_actions", [
        "ADDED_CONTENT", "DELETED_CONTENT", "MODIFIED_CONTENT", "MODIFIED_RULE",
    ]))
    summary_threshold = cfg.get("summary_threshold", 8)

    events, paths = collect_events(cfg)
    log.info("Đọc %d file audit -> %d sự kiện tổng.", len(paths), len(events))

    # Lọc theo watch_actions.
    changes = [e for e in events if e.get("action") in watch]
    log.info("Sự kiện thay đổi cấu hình (watch): %d", len(changes))

    # Dedup.
    seen = load_seen(cfg)
    new_seen = set(seen)
    to_alert = []
    for e in changes:
        key = ap.dedup_key(e)
        if key in seen:
            continue
        new_seen.add(key)
        to_alert.append(e)

    log.info("Sự kiện MỚI cần cảnh báo: %d", len(to_alert))

    if not to_alert:
        save_seen(cfg, new_seen)
        return 0

    appliance = to_alert[0].get("appliance", "MGW")

    if dry_run:
        for e in to_alert:
            print("\n" + tg.build_alert_mgw(e))
        log.info("[DRY-RUN] không gửi Telegram, không lưu seen.")
        return len(to_alert)

    sent = 0
    # Nếu quá nhiều thay đổi trong 1 lần -> gửi tin tổng hợp thay vì spam.
    if len(to_alert) > summary_threshold:
        if tg._send_raw(tgc["bot_token"], tgc["chat_id"], tg.build_alert_summary(to_alert, appliance)):
            sent += 1
    else:
        for e in to_alert:
            if tg._send_raw(tgc["bot_token"], tgc["chat_id"], tg.build_alert_mgw(e)):
                sent += 1
            time.sleep(1.0)

    # Chỉ lưu seen khi đã gửi (tránh mất alert nếu Telegram lỗi toàn bộ).
    if sent > 0 or len(to_alert) > summary_threshold:
        save_seen(cfg, new_seen)

    log.info("Đã gửi %d tin cảnh báo.", sent)
    return sent


def main():
    ap_ = argparse.ArgumentParser(description="MGW audit log -> Telegram alert khi thay đổi cấu hình")
    ap_.add_argument("--config", default="../config/config.json")
    ap_.add_argument("--loop", action="store_true", help="Chạy lặp theo interval_minutes")
    ap_.add_argument("--test", action="store_true", help="Gửi 1 tin test Telegram")
    ap_.add_argument("--dry-run", action="store_true", help="In cảnh báo ra màn hình, KHÔNG gửi/lưu")
    args = ap_.parse_args()

    cfg = load_config(args.config)
    tgc = cfg["telegram"]

    if args.test:
        ok = tg._send_raw(tgc["bot_token"], tgc["chat_id"],
                          tg.build_alert_system("MGW AUDIT MONITOR - TEST",
                                                "Kết nối Telegram OK. Hệ thống giám sát thay đổi cấu hình MGW sẵn sàng.",
                                                severity="recovered"))
        log.info("Test Telegram: %s", "OK" if ok else "FAIL")
        return 0

    if args.loop:
        interval = cfg.get("interval_minutes", 5) * 60
        log.info("LOOP MODE - quét mỗi %d phút.", cfg.get("interval_minutes", 5))
        while True:
            try:
                run_once(cfg, dry_run=args.dry_run)
            except KeyboardInterrupt:
                break
            except Exception as e:
                log.exception("Lỗi run_once: %s", e)
            time.sleep(interval)
        return 0

    run_once(cfg, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
