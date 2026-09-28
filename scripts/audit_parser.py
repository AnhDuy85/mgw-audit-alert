#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_parser.py — Parse audit log McAfee/Trellix Web Gateway (MWG/MGW).

Format audit log (mỗi sự kiện là 1 block, phân cách bằng dòng gạch dưới):

    ________________________________________________________________________________
    Timestamp  : 18/Sep/2026:09:36:38.487 +0700
    User       : truongtrilinh_a
    Action     : DELETED_CONTENT
    Source Name: Whitelist_SVR
    Source Type: LIST<IP>
    Source ID  : com.scur.type.ip.877
    Source Path: /Lists/IP/
    Appliance  : DC-INT-MGW5500F-01
    Details:
       Entry   : 10.4.90.95
       Position: 83

       Entry   : 10.4.27.26
       Position: 66

Trả về list dict, mỗi dict chuẩn hoá 1 sự kiện.

Python stdlib only.
"""

import re
from datetime import datetime


# Dòng phân cách block = chuỗi gạch dưới liên tiếp.
_SEP_RE = re.compile(r"^_{10,}\s*$")
# Dòng field dạng "Key : value" (Key có thể có khoảng trắng: Source Name).
_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z /]*?)\s*:\s*(.*)$")

# Ánh xạ tên field trong log -> khoá chuẩn.
_FIELD_MAP = {
    "Timestamp": "timestamp_raw",
    "User": "user",
    "Action": "action",
    "Source Name": "source_name",
    "Source Type": "source_type",
    "Source ID": "source_id",
    "Source Path": "source_path",
    "Appliance": "appliance",
    "Comment": "comment",
    "Change Comment": "comment",
}


def parse_mgw_timestamp(s):
    """
    '18/Sep/2026:09:36:38.487 +0700' -> ISO '2026-09-18T09:36:38'.
    Trả về (iso_string, date_str, time_str). Nếu parse lỗi trả về raw.
    """
    s = (s or "").strip()
    # Bỏ mili-giây để strptime dễ; giữ timezone offset.
    m = re.match(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", s)
    if not m:
        return s, "", ""
    day, mon, year, hh, mm, ss = m.groups()
    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    }
    try:
        dt = datetime(int(year), months[mon], int(day), int(hh), int(mm), int(ss))
        return dt.strftime("%Y-%m-%dT%H:%M:%S"), dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")
    except (KeyError, ValueError):
        return s, "", ""


def _parse_block(lines):
    """Parse 1 block (list dòng, đã bỏ dòng phân cách) -> dict event."""
    event = {
        "timestamp_raw": "", "user": "", "action": "",
        "source_name": "", "source_type": "", "source_id": "",
        "source_path": "", "appliance": "", "comment": "",
        "details": [], "entries": [],
    }
    in_details = False
    cur_detail = {}

    for line in lines:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped:
            # Dòng trống: kết thúc 1 detail entry (nếu đang gom).
            if cur_detail:
                event["details"].append(cur_detail)
                cur_detail = {}
            continue

        # Bắt đầu phần Details:
        if stripped.rstrip(":").lower() == "details":
            in_details = True
            continue

        # Field cấp trên bám lề trái (raw); field trong Details thụt lề (stripped).
        m = _FIELD_RE.match(raw if not in_details else stripped)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()

        if not in_details and key in _FIELD_MAP:
            event[_FIELD_MAP[key]] = val
        elif in_details:
            # Trong Details: gom Entry/Position và các key con khác.
            cur_detail[key] = val
            if key.lower() == "entry":
                # strip để khử space ẩn (tránh '10.4.27.119' != '10.4.27.119 ').
                event["entries"].append(val.strip())

    if cur_detail:
        event["details"].append(cur_detail)

    # Khử TRÙNG LẶP entries ngay ở tầng parser (mọi consumer đều nhận sạch).
    # MODIFIED_CONTENT hay ghi mỗi entry 2 lần (old/new position) -> IP trùng.
    event["entries"] = list(dict.fromkeys(event["entries"]))

    # Chuẩn hoá timestamp.
    iso, d, t = parse_mgw_timestamp(event["timestamp_raw"])
    event["timestamp"] = iso
    event["date"] = d
    event["time"] = t
    return event


def parse_audit_text(text):
    """Parse toàn bộ nội dung audit log -> list event dict."""
    events = []
    block = []
    for line in text.splitlines():
        if _SEP_RE.match(line):
            if block:
                ev = _parse_block(block)
                if ev.get("action"):  # chỉ giữ block có Action
                    events.append(ev)
                block = []
        else:
            block.append(line)
    # block cuối (không có separator sau).
    if block:
        ev = _parse_block(block)
        if ev.get("action"):
            events.append(ev)
    return events


def parse_audit_file(path, encoding="utf-8", errors="replace"):
    """Đọc + parse 1 file audit log."""
    with open(path, "r", encoding=encoding, errors=errors) as f:
        return parse_audit_text(f.read())


def dedup_key(event):
    """Khoá dedup 1 sự kiện: timestamp + user + action + source + entries."""
    return (
        event.get("timestamp_raw", ""),
        event.get("user", ""),
        event.get("action", ""),
        event.get("source_name", ""),
        "|".join(event.get("entries", [])),
    )
