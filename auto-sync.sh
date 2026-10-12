#!/usr/bin/env bash
# ============================================================
#  auto-sync.sh — Tu dong commit + push thay doi len GitHub.
#  Goi boi Kiro Agent Hook (PostFileSave) hoac chay tay.
#
#  An toan:
#   - Chi chay neu dang trong git repo va CO thay doi.
#   - KHONG commit file bi .gitignore (secret.json, logs...) -> git tu bo qua.
#   - Dung `git add -A` nhung .gitignore da chan file nhay cam.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

# Chi chay trong git repo.
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Khong phai git repo, bo qua."; exit 0; }

# Khong co thay doi -> thoat im lang.
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  echo "Khong co thay doi de sync."
  exit 0
fi

# Canh bao neu lo file secret (dieu khong nen xay ra vi da .gitignore).
if git status --porcelain | grep -E "secret\.json|\.env$|config\.local" >/dev/null 2>&1; then
  echo "⚠️  Phat hien file nhay cam trong thay doi - DUNG auto-sync de tranh lo secret."
  echo "    Kiem tra .gitignore va git status."
  exit 1
fi

ts="$(date '+%Y-%m-%d %H:%M:%S')"
git add -A
git commit -m "auto-sync: ${ts}" >/dev/null 2>&1 || { echo "Khong co gi de commit."; exit 0; }

# Push; neu that bai (mat mang...) bao loi nhung khong lam hong repo.
if git push >/dev/null 2>&1; then
  echo "✅ Da sync len GitHub ($ts)."
else
  echo "⚠️  Commit xong nhung PUSH that bai (kiem tra mang/credential). Push lai sau bang: git push"
  exit 1
fi
