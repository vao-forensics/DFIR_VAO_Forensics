#!/usr/bin/env python3
"""Deliver finished audio results that nobody delivered.

WHY THIS EXISTS (2026-08-19 incident)
------------------------------------
A 161-minute lecture was transcribed, translated and voiced successfully: the sidecar
logged `audio-translate-ua out mp3 size=41727208 segs=24` and wrote the MP3 plus both
transcripts. The user got none of it. The progress bar froze at 87% and stayed frozen,
no error was raised, the container never restarted and no connection was left hanging.
The result simply sat on disk while the owner assumed the job had died.

The in-process delivery path is fire-and-forget: one daemon thread holds the only
reference to "this result belongs to that chat". If that thread stops for any reason -
and it did - the finished work is orphaned and nothing on the system notices.

This reconciler removes the whole class of failure instead of chasing the one cause.
It owns no part of the pipeline: it just looks at what is on disk, and delivers what
was never handed over. Idempotent by a `.delivered` marker next to each file, so it
can run every few minutes forever and never send the same thing twice.
"""
import json
import os
import sys
import time
import urllib.request

RESULTS = os.getenv("DFIR_AUDIO_RESULTS_DIR", "/audio_results")
# HARD RULE (owner-only-dm): bot files go to the owner and nobody else.
OWNER_CHAT = os.getenv("DFIR_OWNER_CHAT_ID", "CHANGE_ME_OWNER_CHAT_ID")
TOKEN = os.getenv("DFIR_TG_BOT_TOKEN", "")
# Ignore anything still being written; the sidecar writes the mp3 last.
SETTLE_SECONDS = int(os.getenv("DFIR_AUDIO_SETTLE_SEC", "180"))
API = "https://api.telegram.org/bot%s/%s"


def log(msg):
    print("%s [audio-reconcile] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


def _post(method, fields, files=None):
    """Minimal multipart POST. Returns (ok, description)."""
    boundary = "----dfirreconcile%d" % int(time.time() * 1000)
    body = []
    for k, v in fields.items():
        body.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                     % (boundary, k, v)).encode("utf-8"))
    for k, (name, blob, ctype) in (files or {}).items():
        body.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                     "Content-Type: %s\r\n\r\n" % (boundary, k, name, ctype)).encode("utf-8"))
        body.append(blob)
        body.append(b"\r\n")
    body.append(("--%s--\r\n" % boundary).encode("utf-8"))
    data = b"".join(body)
    req = urllib.request.Request(
        API % (TOKEN, method), data=data,
        headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
            return bool(d.get("ok")), ""
    except Exception as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")[:200]
        except Exception:
            detail = str(e)[:200]
        return False, detail


def _pretty(name):
    """5cb614d2..._vebinar_1_polihraf_gmt20260814_ua.mp3 -> vebinar_1_polihraf_gmt20260814_ua.mp3"""
    parts = name.split("_", 1)
    return parts[1] if len(parts) == 2 and len(parts[0]) == 32 else name


def deliver(path):
    name = os.path.basename(path)
    size = os.path.getsize(path)
    pretty = _pretty(name)
    is_audio = name.lower().endswith((".mp3", ".wav"))
    # Telegram caps bot uploads at 50 MB; above that a link is the only option.
    if size > 49 * 1024 * 1024:
        url = "%s/%s" % (os.getenv("DFIR_AUDIO_BASE_URL",
                                   "http://CHANGE_ME_DFIR_LINK_IP:8080/audio"), name)
        ok, err = _post("sendMessage", {
            "chat_id": OWNER_CHAT,
            "text": ("✅ Результат обробки аудіо був готовий, але не дійшов до вас — "
                     "надсилаю автоматично.\n\n%s (%.0f МБ)\n\n⬇️ %s"
                     % (pretty, size / 1048576.0, url))})
        return ok, err
    with open(path, "rb") as fh:
        blob = fh.read()
    method = "sendAudio" if is_audio else "sendDocument"
    field = "audio" if is_audio else "document"
    ctype = "audio/mpeg" if is_audio else "text/plain"
    ok, err = _post(method, {
        "chat_id": OWNER_CHAT,
        "caption": ("✅ Готовий результат, який не дійшов до вас — надсилаю автоматично."
                    if is_audio else pretty)},
        {field: (pretty, blob, ctype)})
    return ok, err


def main():
    if not TOKEN:
        log("DFIR_TG_BOT_TOKEN не заданий — нічого не роблю")
        return 2
    if not os.path.isdir(RESULTS):
        log("немає теки %s" % RESULTS)
        return 2

    seed = "--seed" in sys.argv          # mark everything present as already delivered
    now = time.time()
    sent = 0
    for name in sorted(os.listdir(RESULTS)):
        if name.endswith((".delivered", ".prog")):
            continue
        path = os.path.join(RESULTS, name)
        if not os.path.isfile(path):
            continue
        marker = path + ".delivered"
        if os.path.exists(marker):
            continue
        if now - os.path.getmtime(path) < SETTLE_SECONDS:
            continue                      # still being written
        if seed:
            open(marker, "w").write("seeded %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            continue
        ok, err = deliver(path)
        if ok:
            open(marker, "w").write("delivered %s\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            log("віддано: %s" % name)
            sent += 1
        else:
            # No marker on failure: the next run retries. That is the entire point.
            log("НЕ віддано: %s -> %s" % (name, err))
    if seed:
        log("позначено наявні файли як уже віддані")
    elif sent:
        log("надіслано %d файл(ів)" % sent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
