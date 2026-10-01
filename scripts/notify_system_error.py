#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
notify_system_error.py — Gui 1 canh bao Telegram khi KHONG lay duoc audit log
tu MGW (dung boi playbook.yml phuong an 1 khi Ansible SSH that bai).

Usage:
    python notify_system_error.py <mgw_host> <rc>

Doc telegram {bot_token, chat_id} tu config/secret.json. Stdlib only.
"""

import sys
import json
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "MGW"
    rc = sys.argv[2] if len(sys.argv) > 2 else "?"

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import telegram_notify as tg

    sec_path = Path(__file__).resolve().parent.parent / "config" / "secret.json"
    tg_cfg = {}
    if sec_path.exists():
        try:
            tg_cfg = json.loads(sec_path.read_text(encoding="utf-8-sig")).get("telegram", {})
        except Exception:
            tg_cfg = {}
    token = tg_cfg.get("bot_token", "")
    chat = tg_cfg.get("chat_id", "")
    if not token or not chat:
        print("Thieu telegram token/chat_id trong secret.json - khong gui duoc.")
        return 1

    msg = (f"Ansible khong lay duoc audit log tu {host} (rc={rc}).\n"
           "Kiem tra: ket noi mang toi MGW, user/password pci-dss, "
           "duong dan /opt/mwg/log/audit, quyen doc file.")
    ok = tg._send_raw(token, chat, tg.build_alert_system(
        "MGW AUDIT - LOI LAY LOG (Ansible)", msg, severity="critical"))
    print("Da gui alert loi Telegram." if ok else "Gui alert that bai.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
