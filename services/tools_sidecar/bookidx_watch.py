"""bookidx_watch.py — drops-folder watcher for the OFFLINE Study exam index.

Runs in a container built from the tools-sidecar image (has requests + pikepdf +
the bookidx engine baked at /app/bookidx). Polls BOOKIDX_INBOX; for each new PDF it POSTs
to the sidecar /bookidx/index endpoint (regex + LOCAL LLM only — content never leaves
the box), writes the resulting ZIP to BOOKIDX_OUTPUT/<name>/bookidx_index.zip (served by
the file-server), and notifies the user via the bot webhooks. Password-protected
PDFs: the sidecar returns 422 -> we ask the user (once) via /tool-needpass and skip
until they send the password (written next to the file as <pdf>.password).

Mirrors translate_watch.py. Resume-safe: finished sources move to inbox/done.
"""
import os
import time
import glob
import shutil
import json

import requests

INBOX = os.environ.get("BOOKIDX_INBOX", "/bookidx_inbox")
OUTPUT = os.environ.get("BOOKIDX_OUTPUT", "/translate_output")
SIDECAR = os.environ.get("SIDECAR_URL", "http://tools-sidecar:8799").rstrip("/")
BOT = os.environ.get("BOT_URL", "http://case-maintainer:8787").rstrip("/")
POLL = int(os.environ.get("BOOKIDX_POLL_SECONDS", "15"))
CKPT = os.environ.get("BOOKIDX_CKPT_DIR", "/bookidx_ckpt")


def status(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S ") + msg, flush=True)


def _read(path):
    try:
        return open(path, encoding="utf-8").read().strip()
    except Exception:
        return ""


def _post_bot(path, body):
    try:
        requests.post(BOT + "/" + path, json=body, timeout=20)
    except Exception as e:
        status("post %s failed: %s" % (path, str(e)[:120]))


def _cleanup_sidecars(src):
    for ext in (".chatid", ".password", ".needpass"):
        try:
            os.remove(src + ext)
        except Exception:
            pass


def _progress_thread(book, chatid, since, stop):
    """Turn the engine checkpoint into a progress bar.

    Indexing a 1400-page book takes hours and used to show nothing at all. The engine
    already writes one checkpoint line per finished chunk plus _current.json naming the
    running job - so watching those two files is enough, and the engine keeps running
    untouched. The name cannot be recomputed here: the engine indexes a normalised copy of
    the PDF, whose bytes differ from the file in the inbox.
    """
    import threading
    if not chatid:
        return None

    def _job():
        try:
            with open(os.path.join(CKPT, "_current.json"), encoding="utf-8") as fh:
                j = json.load(fh)
            # ignore a pointer left by an earlier run
            if float(j.get("started") or 0) + 5 < since:
                return None
            return j
        except Exception:
            return None

    def _done(key):
        try:
            with open(os.path.join(CKPT, key + ".jsonl"), "rb") as fh:
                return sum(1 for _ in fh)
        except Exception:
            return 0

    def _run():
        started = False
        while not stop.is_set():
            stop.wait(20)
            if stop.is_set():
                break
            j = _job()
            tot = int((j or {}).get("chunks") or 0)
            if not tot:
                continue
            if not started:
                _post_bot("tool-progress", {"chat_id": chatid, "book": book, "op": "bookidx",
                                            "done": 0, "pages": tot, "phase": "start"})
                started = True
            _post_bot("tool-progress", {"chat_id": chatid, "book": book, "op": "bookidx",
                                        "done": min(_done(j.get("key") or ""), tot),
                                        "pages": tot, "phase": "progress"})

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    return th


def process(src):
    book = os.path.basename(src)                 # folder + link key
    name = os.path.splitext(book)[0] or "bookidx"
    chatid = _read(src + ".chatid")
    pw = _read(src + ".password")
    needpass = src + ".needpass"

    status("START %s (chat=%s)" % (book, chatid))
    import threading as _th
    _stop = _th.Event()
    _progress_thread(name, chatid, time.time(), _stop)
    try:
        with open(src, "rb") as fh:
            files = {"file": (book, fh, "application/pdf")}
            data = {"password": pw, "book_label": name, "page_offset": "0"}
            r = requests.post(SIDECAR + "/bookidx/index", files=files, data=data,
                              timeout=int(os.environ.get("BOOKIDX_TIMEOUT", "3600")))
    except Exception as e:
        _stop.set()
        status("ERROR %s: sidecar post failed: %s" % (book, str(e)[:200]))
        _post_bot("tool-done", {"chat_id": chatid, "book": name, "status": "error",
                                "op": "bookidx"})
        shutil.move(src, os.path.join(INBOX, "done", book))
        _cleanup_sidecars(src)
        return

    _stop.set()

    # Encrypted PDF: ask the user for the password (once) and wait.
    if r.status_code == 422:
        # A supplied password was REJECTED -> stop hammering the sidecar every poll
        # with the same wrong password. Rename it aside so the loop's needpass-skip
        # (needpass exists AND no .password) kicks in and we wait for a NEW password.
        if pw:
            try:
                os.replace(src + ".password", src + ".password.rejected")
                status("BADPASS %s (rejected, awaiting new password)" % book)
            except Exception:
                pass
        if not os.path.isfile(needpass):
            open(needpass, "w").close()
            status("NEEDPASS %s" % book)
            _post_bot("tool-needpass", {"chat_id": chatid, "book": book, "op": "bookidx"})
        return  # leave the file; retry only after a NEW password arrives

    if r.status_code == 200:
        outdir = os.path.join(OUTPUT, name)
        os.makedirs(outdir, exist_ok=True)
        zip_path = os.path.join(outdir, "bookidx_index.zip")
        with open(zip_path, "wb") as zf:
            zf.write(r.content)
        entries = r.headers.get("X-Bookidx-Entries", "?")
        status("DONE %s (%s entries) -> %s" % (book, entries, zip_path))
        _post_bot("tool-done", {"chat_id": chatid, "book": name, "status": "done",
                                "op": "bookidx", "pages": entries})
        shutil.move(src, os.path.join(INBOX, "done", book))
        _cleanup_sidecars(src)
        return

    # Any other error: report and stop retrying this file.
    status("ERROR %s: sidecar %s %s" % (book, r.status_code, r.text[:160]))
    _post_bot("tool-done", {"chat_id": chatid, "book": name, "status": "error",
                            "op": "bookidx"})
    shutil.move(src, os.path.join(INBOX, "done", book))
    _cleanup_sidecars(src)


def main():
    os.makedirs(INBOX, exist_ok=True)
    os.makedirs(OUTPUT, exist_ok=True)
    os.makedirs(os.path.join(INBOX, "done"), exist_ok=True)
    status("bookidx-watcher started (inbox=%s out=%s sidecar=%s)" % (INBOX, OUTPUT, SIDECAR))
    while True:
        try:
            pdfs = sorted(glob.glob(os.path.join(INBOX, "*.pdf")) +
                          glob.glob(os.path.join(INBOX, "*.PDF")))
            for src in pdfs:
                # Skip a file that is waiting on a password (no .password yet).
                if os.path.isfile(src + ".needpass") and not os.path.isfile(src + ".password"):
                    continue
                process(src)
        except Exception as e:
            status("loop error: %s" % str(e)[:300])
        time.sleep(POLL)


if __name__ == "__main__":
    main()
