#!/usr/bin/env python3
"""Runs INSIDE open-webui: set a new password for one account (default: the first admin).
env NEW_PW (required), EMAIL (optional). Prints the e-mail it changed, never the password."""
import asyncio, os, sqlite3, sys

sys.path.insert(0, "/app/backend")
from open_webui.utils.auth import get_password_hash  # noqa: E402

pw = os.environ.get("NEW_PW", "")
if len(pw) < 10:
    sys.exit("NEW_PW must have 10+ characters")
db = sqlite3.connect("/app/backend/data/webui.db")
email = os.environ.get("EMAIL") or db.execute(
    "select email from user where role='admin' order by created_at limit 1").fetchone()[0]
h = get_password_hash(pw)
if asyncio.iscoroutine(h):
    h = asyncio.run(h)
n = db.execute("update auth set password=? where email=?", (h, email)).rowcount
db.commit()
if n != 1:
    sys.exit("account not found: " + email)
print(email)
