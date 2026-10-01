#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
telegram_notify.py — Gửi cảnh báo Telegram cho thay đổi cấu hình MGW.

Python stdlib only (urllib) - chạy được trên appliance/AWX EE không cần pip.
"""

import json
import time
import logging
import urllib.request
from datetime import datetime

log = logging.getLogger("telegram")

_MAX_LEN = 4096

# Icon + nhãn theo action MGW.
_ACTION_HEADER = {
    "ADDED_CONTENT":    ("🟢", "THÊM NỘI DUNG (ADD)"),
    "MODIFIED_CONTENT": ("🟡", "SỬA NỘI DUNG (MODIFY)"),
    "MODIFIED_RULE":    ("🟠", "SỬA RULE (MODIFY RULE)"),
    "DELETED_CONTENT":  ("🔴", "XÓA NỘI DUNG (DELETE)"),
    "ADDED_RULE":       ("🟢", "THÊM RULE (ADD RULE)"),
    "DELETED_RULE":     ("🔴", "XÓA RULE (DELETE RULE)"),
    "FILE_DOWNLOAD":    ("📥", "TẢI FILE (DOWNLOAD/EXPORT)"),
}


def _send_raw(token, chat_id, text, max_retries=3):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text[:_MAX_LEN],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})

    last_exc = None
    for attempt in range(1, max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read().decode("utf-8"))
            if body.get("ok"):
                log.info("Telegram OK msg_id=%s", body["result"]["message_id"])
                return True
            log.error("Telegram FAIL (nghiệp vụ, không retry): %s", body)
            return False
        except Exception as e:
            last_exc = e
            log.warning("Telegram exception (lần %d/%d): %s", attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(2 * attempt)
    log.error("Telegram FAIL sau %d lần - lỗi cuối: %s", max_retries, last_exc)
    return False


def _esc(s):
    """Escape ký tự HTML để không vỡ parse_mode=HTML."""
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_alert_mgw(ev):
    """
    Tạo tin cảnh báo Telegram cho 1 sự kiện thay đổi cấu hình MGW.
    ev = dict từ audit_parser.parse_audit_*.
    """
    action = ev.get("action", "")
    icon, verb = _ACTION_HEADER.get(action, ("⚠️", action or "UNKNOWN"))

    user = ev.get("user", "—")
    src_name = ev.get("source_name", "") or "—"
    src_type = ev.get("source_type", "") or "—"
    src_path = ev.get("source_path", "") or ""
    appliance = ev.get("appliance", "") or "MGW"
    date_s = ev.get("date", "")
    time_s = ev.get("time", "")
    entries = ev.get("entries", []) or []

    lines = [
        f"{icon} <b>{verb}</b>",
        f"{'─' * 30}",
        f"🖥 <b>Appliance :</b> <code>{_esc(appliance)}</code>",
        f"👤 <b>User      :</b> <code>{_esc(user)}</code>",
        f"📂 <b>Đối tượng :</b> <code>{_esc(src_name)}</code>",
        f"🏷  <b>Loại      :</b> <code>{_esc(src_type)}</code>",
    ]
    if src_path:
        lines.append(f"📁 <b>Đường dẫn :</b> <code>{_esc(src_path)}</code>")
    lines.append(f"🕐 <b>Thời gian :</b> <code>{_esc(date_s)} {_esc(time_s)}</code>")

    # entries đã được khử trùng lặp ở tầng parser (audit_parser._parse_block).
    if entries:
        shown = entries[:15]
        lines.append(f"📝 <b>Chi tiết ({len(entries)}):</b>")
        for e in shown:
            lines.append(f"   • <code>{_esc(e)}</code>")
        if len(entries) > len(shown):
            lines.append(f"   • ... và {len(entries) - len(shown)} mục khác")

    # Comment (nếu audit log ghi comment cho thay đổi).
    comment = ev.get("comment", "")
    if comment:
        lines.append(f"💬 <b>Comment   :</b> <code>{_esc(comment)}</code>")

    return "\n".join(lines)


def build_alert_summary(events, appliance="MGW"):
    """Tin tổng hợp khi 1 lần quét có nhiều thay đổi."""
    from collections import Counter
    cnt = Counter(e.get("action", "?") for e in events)
    users = sorted({e.get("user", "?") for e in events})
    lines = [
        "📊 <b>MGW — TỔNG HỢP THAY ĐỔI CẤU HÌNH</b>",
        f"{'─' * 30}",
        f"🖥 <b>Appliance :</b> <code>{_esc(appliance)}</code>",
        f"🕐 <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>",
        f"👤 <b>User(s)   :</b> {', '.join(_esc(u) for u in users)}",
        f"{'─' * 30}",
        f"🔢 <b>Tổng thay đổi:</b> {len(events)}",
    ]
    for act, n in cnt.most_common():
        icon = _ACTION_HEADER.get(act, ("•", act))[0]
        lines.append(f"   {icon} {_esc(act)}: {n}")
    return "\n".join(lines)


def build_alert_system(title, message, severity="warning"):
    """Cảnh báo về chính hệ thống monitor (lỗi đọc log, khôi phục...)."""
    icon = {"warning": "⚠️", "critical": "🆘", "recovered": "✅"}.get(severity, "⚠️")
    lines = [
        f"{icon} <b>{_esc(title)}</b>",
        f"{'─' * 30}",
        _esc(message),
        f"{'─' * 30}",
        f"🕐 <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>",
    ]
    return "\n".join(lines)
