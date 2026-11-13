"""Batch translation watcher — drops-folder → UK side-by-side HTML.

Runs in a container built from the tools-sidecar image (has PyMuPDF + pikepdf +
the course_translate engine baked at /app). Polls an inbox folder; for each new
PDF it produces OUTPUT/<book>/index.html (original page image left, UK translation
right), then moves the source to inbox/done. Resume-safe (skips finished pages).

The user drops PDFs (+ a _password.txt for protected Study files) into the inbox
over ZeroTier (scp/WinSCP or a Samba share). Nothing leaves the box — translation
is the local translate-9b model on the host GPUs.
"""
import os, time, glob, shutil, sys

sys.path.insert(0, "/app")
import course_translate as eng  # baked into the sidecar image

INBOX = os.environ.get("TR_INBOX", "/translate_inbox")
OUTPUT = os.environ.get("TR_OUTPUT", "/translate_output")

eng.BACKEND = "openai"
eng.ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://192.168.100.1:1234").rstrip("/")
# uncensored-32b (qwen) beats translate-9b on DFIR jargon: it keeps firewall/backdoor/
# registry in English instead of literal mistranslations ("вогняне угруповання").
eng.MODEL = os.environ.get("SBS_MODEL", "uncensored-32b")
eng.WORKERS = int(os.environ.get("SBS_WORKERS", "4"))  # lower for the 32b tensor-split model
eng.SYSTEM_PROMPT = (
    "Ти професійний перекладач технічної літератури з цифрової криміналістики (DFIR). "
    "Сам визнач мову оригіналу і перекладай УКРАЇНСЬКОЮ, точно й природно, як жива людина. "
    "Технічні терміни та назви інструментів (firewall, backdoor, registry, malware, hash, "
    "payload, exploit, EDR, Volatility, Wireshark, PowerShell тощо) ЛИШАЙ англійською — не "
    "перекладай їх дослівно. Зберігай поділ на абзаци. Виводь ЛИШЕ переклад, без коментарів."
)


def status(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line, flush=True)
    try:
        with open(os.path.join(OUTPUT, "_STATUS.txt"), "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _notify(chat_id, book, status_str, pages):
    if not chat_id:
        return
    try:
        import urllib.request, json
        body = json.dumps({"chat_id": chat_id, "book": book, "status": status_str,
                           "pages": pages}).encode()
        url = os.environ.get("NOTIFY_URL", "http://case-maintainer:8787/tool-done")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:
        status("notify failed for %s: %s" % (book, str(e)[:120]))


def _post_bot(path, body):
    try:
        import urllib.request, json
        url = "http://case-maintainer:8787/" + path
        urllib.request.urlopen(urllib.request.Request(
            url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=20).read()
    except Exception as e:
        status("post %s failed: %s" % (path, str(e)[:100]))


def _detect_lang(src, pw):
    """Detect the source language from the first pages (one short LLM call)."""
    try:
        import fitz
        doc = fitz.open(src)
        if doc.needs_pass:
            doc.authenticate(pw)
        txt = ""
        for pno in range(min(3, doc.page_count)):
            txt += " ".join(eng.page_paragraphs(doc[pno]))
            if len(txt) > 400:
                break
        doc.close()
        txt = txt[:600].strip()
        if not txt:
            return "невідома"
        import urllib.request, json
        body = json.dumps({"model": eng.MODEL, "temperature": 0, "max_tokens": 8, "messages": [
            {"role": "system", "content": "Визнач мову тексту. Відповідай ОДНИМ словом українською (англійська, російська, німецька, українська тощо)."},
            {"role": "user", "content": txt}]}).encode()
        r = json.load(urllib.request.urlopen(urllib.request.Request(
            eng.ENDPOINT + "/v1/chat/completions", data=body, headers={"Content-Type": "application/json"}), timeout=60))
        return r["choices"][0]["message"]["content"].strip().split()[0][:20]
    except Exception:
        return "невідома"


def _page_count(src, pw):
    try:
        import fitz
        doc = fitz.open(src)
        if doc.needs_pass:
            doc.authenticate(pw)
        n = doc.page_count
        doc.close()
        return n
    except Exception:
        return 0


def _prompt_for_target(target):
    return (
        "Ти професійний перекладач технічної літератури з цифрової криміналістики (DFIR). "
        "Сам визнач мову оригіналу і перекладай мовою: %s. Точно й природно, як жива людина. "
        "Технічні терміни (firewall, backdoor, registry, malware, hash, payload, exploit, EDR, "
        "Volatility, Wireshark, PowerShell) ЛИШАЙ англійською. Зберігай абзаци. Виводь ЛИШЕ переклад." % target)


def read_password(src):
    """Per-file password: <pdf>.password (written by the bot after the user sends it)."""
    pf = src + ".password"
    if os.path.isfile(pf):
        try:
            return open(pf, encoding="utf-8").read().strip()
        except Exception:
            pass
    return ""


def _needpass(chat_id, book):
    """Tell the bot this file is password-protected so it asks the user."""
    if not chat_id:
        return
    try:
        import urllib.request, json
        body = json.dumps({"chat_id": chat_id, "book": book}).encode()
        url = os.environ.get("NEEDPASS_URL", "http://case-maintainer:8787/tool-needpass")
        urllib.request.urlopen(urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}), timeout=20).read()
    except Exception as e:
        status("needpass notify failed %s: %s" % (book, str(e)[:120]))


def main():
    os.makedirs(INBOX, exist_ok=True)
    os.makedirs(OUTPUT, exist_ok=True)
    os.makedirs(os.path.join(INBOX, "done"), exist_ok=True)
    status("translate-watcher started (inbox=%s out=%s model=%s)" % (INBOX, OUTPUT, eng.MODEL))
    while True:
        try:
            pdfs = sorted(glob.glob(os.path.join(INBOX, "*.pdf")) +
                          glob.glob(os.path.join(INBOX, "*.PDF")))
            for src in pdfs:
                name = os.path.splitext(os.path.basename(src))[0]
                chatid = ""
                cid_path = src + ".chatid"
                if os.path.isfile(cid_path):
                    try:
                        chatid = open(cid_path, encoding="utf-8").read().strip()
                    except Exception:
                        pass
                needpass = src + ".needpass"
                pw = read_password(src)
                # Password gate: if the PDF is protected and we don't have the password
                # yet, ask the user (once) and skip until they send it.
                try:
                    import pikepdf as _pk
                    with _pk.open(src, password=pw):
                        pass
                except Exception as _pe:
                    if type(_pe).__name__ == 'PasswordError':
                        if not os.path.isfile(needpass):
                            open(needpass, "w").close()
                            status("NEEDPASS %s" % name)
                            _needpass(chatid, os.path.basename(src))
                        continue
                    # not a password problem — let process_book surface it below
                if os.path.isfile(needpass):
                    os.remove(needpass)
                eng.PDF_PASSWORD = pw
                eng.OUT_DIR = OUTPUT
                eng.DECDIR = os.path.join(OUTPUT, "_decrypted")
                bk = os.path.basename(src)
                npages = _page_count(src, pw)
                lang = _detect_lang(src, pw)
                status("START %s (%d p, lang=%s)" % (name, npages, lang))
                _post_bot("tool-progress", {"chat_id": chatid, "book": bk, "done": 0,
                                            "pages": npages, "lang": lang, "phase": "start"})
                import threading as _th, time as _t2
                _stopf = {"v": False}

                def _mon(_nm=name, _cid=chatid, _np=npages, _b=bk):
                    while not _stopf["v"]:
                        _t2.sleep(15)
                        if _stopf["v"]:
                            break
                        d = len(glob.glob(os.path.join(OUTPUT, _nm, "frag", "p*.html")))
                        _post_bot("tool-progress", {"chat_id": _cid, "book": _b, "done": d,
                                                    "pages": _np, "phase": "progress"})

                _th.Thread(target=_mon, daemon=True).start()
                try:
                    eng.process_book(src)
                    _stopf["v"] = True
                    pages = len(glob.glob(os.path.join(OUTPUT, name, "frag", "p*.html")))
                    status("DONE %s (%d p) -> %s/%s/index.html" % (name, pages, OUTPUT, name))
                    _notify(chatid, name, "done", pages)
                    shutil.move(src, os.path.join(INBOX, "done", bk))
                    for ext in (".chatid", ".password", ".asked", ".target", ".needpass"):
                        try:
                            os.remove(src + ext)
                        except Exception:
                            pass
                except Exception as e:
                    _stopf["v"] = True
                    status("ERROR %s: %s" % (name, str(e)[:300]))
                    _notify(chatid, name, "error", None)
        except Exception as e:
            status("loop error: %s" % str(e)[:300])
        time.sleep(15)


if __name__ == "__main__":
    main()
