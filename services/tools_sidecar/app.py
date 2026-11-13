# =============================================================================
#  tools-sidecar — native forensic file utilities HTTP API
# -----------------------------------------------------------------------------
#  Runs in a Debian slim container (glibc) so heavy native libs work without
#  compiling on Alpine. The Alpine bot (case-maintainer) proxies uploaded files
#  here and returns the processed file/JSON to Telegram.
#
#  Endpoints (all POST, multipart/form-data with a "file" part unless noted):
#    POST /health                 -> {"ok": true, ...}          (GET allowed too)
#    POST /pdf/unlock             file + password  -> decrypted PDF bytes
#    POST /pdf/translate          file             -> EN->UK translated PDF bytes
#    POST /pdf/watermark          file             -> cleaned PDF bytes
#    POST /ocr                    file [+ lang]    -> searchable PDF bytes
#    POST /meta                   file             -> metadata JSON
#    POST /translate/extract      file             -> {"text": "..."} JSON
#
#  IMPORTANT — translation policy:
#    The sidecar does NOT translate. Translation is performed by the BOT using
#    its existing local LLM (build_chat_payload), so evidence text never leaves
#    the VM and no new model is introduced. The sidecar only EXTRACTS the text
#    from PDF/DOCX/TXT (a native-lib job) and hands it back to the bot, which
#    chunks + translates it via the LLM. Hence /translate/extract, not
#    /translate. This keeps a clean separation: sidecar = native extraction,
#    bot = LLM intelligence.
#
#  Forensic hygiene (applies to every endpoint):
#    * Each request works inside its own private tempfile.mkdtemp() directory.
#    * That directory is ALWAYS deleted in a finally block (no evidence residue).
#    * We log ONLY the SHA-256 of inputs/outputs and sizes — never file contents,
#      never passwords. Passwords are dropped from memory immediately after use.
#    * A hard size cap rejects oversized uploads (Telegram caps at 20 MB anyway).
# =============================================================================
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile

from flask import Flask, request, jsonify, Response

# --- native libraries (present only in this Debian sidecar) ------------------
import pikepdf                      # PDF decrypt/save (qpdf backend)
import fitz                         # PyMuPDF — watermark removal, PDF text/meta
import ocrmypdf                     # OCR -> searchable PDF (Tesseract + Ghostscript)
from PIL import Image               # EXIF metadata
from PIL.ExifTags import TAGS, GPSTAGS
import datetime as _dt   # PDF/EXIF date normalisation for readable /meta report

app = Flask(__name__)

# ── logging ──────────────────────────────────────────────────────────────────
_h = logging.StreamHandler()
_h.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s sidecar: %(message)s'))
app.logger.addHandler(_h)
app.logger.setLevel(logging.INFO)

# ── limits ───────────────────────────────────────────────────────────────────
MAX_BYTES = int(os.getenv('SIDECAR_MAX_BYTES', str(2 * 1024 * 1024 * 1024)))  # 2 GB (large audio/video lectures)
OCR_DEFAULT_LANG = os.getenv('SIDECAR_OCR_LANG', 'ukr+eng')
# Tessdata path for PyMuPDF OCR (raster watermark detection). Container ships
# Tesseract 5 here; override via env if the image layout changes.
WM_TESSDATA = os.getenv('SIDECAR_TESSDATA', '/usr/share/tesseract-ocr/5/tessdata/')
WM_OCR_DPI  = int(os.getenv('SIDECAR_WM_OCR_DPI', '150'))
# Flask hard cap (defence in depth on top of our own check)
HIVE_MAX = int(os.getenv('SIDECAR_HIVE_MAX', str(420 * 1024 * 1024)))  # large registry hives
app.config['MAX_CONTENT_LENGTH'] = max(MAX_BYTES, HIVE_MAX) + (1 * 1024 * 1024)


# ── helpers ──────────────────────────────────────────────────────────────────
def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _recv_file():
    """Return (raw_bytes, original_filename) from the multipart 'file' part.

    Raises ValueError with a Ukrainian-safe message on any problem so the caller
    can surface a clean 4xx. We read the whole file into memory (inputs are
    capped at a few MB) then immediately validate the size.
    """
    f = request.files.get('file')
    if f is None or not f.filename:
        raise ValueError("no_file")
    data = f.read()
    if not data:
        raise ValueError("empty_file")
    if len(data) > MAX_BYTES:
        raise ValueError("too_large")
    return data, os.path.basename(f.filename)


def _pdf_response(out_path: str, download_name: str) -> Response:
    """Stream a produced PDF back as application/pdf with a hash-only log line."""
    with open(out_path, 'rb') as fh:
        out_bytes = fh.read()
    app.logger.info("out pdf sha256=%s size=%d name=%s",
                    _sha256(out_bytes), len(out_bytes), download_name)
    resp = Response(out_bytes, mimetype='application/pdf')
    resp.headers['Content-Disposition'] = f'attachment; filename="{download_name}"'
    return resp


def _err(code: str, http: int = 400):
    """Uniform JSON error. `code` is a stable machine token; the BOT maps it to a
    Ukrainian user message (so localisation lives in one place, in the bot)."""
    return jsonify({'ok': False, 'error': code}), http


# =============================================================================
#  /health
# =============================================================================
@app.route('/health', methods=['GET', 'POST'])
def health():
    return jsonify({
        'ok': True,
        'service': 'tools-sidecar',
        'pikepdf': pikepdf.__version__,
        'pymupdf': fitz.VersionBind,
        'ocrmypdf': getattr(ocrmypdf, '__version__', 'unknown'),
        'ocr_lang': OCR_DEFAULT_LANG,
        'max_bytes': MAX_BYTES,
    })


# =============================================================================
#  /pdf/unlock  — remove a known password / strip encryption (NOT a cracker)
#  Body: multipart file=<pdf>, form field password=<str> (may be empty for the
#        owner-password-only case which opens with no user password).
# =============================================================================
# =============================================================================
#  /forensic/ntlm  — offline local NTLM from a SAM + SYSTEM hive pair
#  (impacket LocalOperations + SAMHashes, isRemote=False). Body: multipart
#  sam=<SAM hive> system=<SYSTEM hive>. Returns {ok, accounts:[{username,rid,lm,nt}]}.
#  Defensive forensics ONLY — parses offline hives on this server; never a live host.
# =============================================================================
# =============================================================================
#  /forensic/sysinfo  - offline OS fingerprint from SOFTWARE (+ optional SYSTEM)
#  hive via impacket.winregistry. Body: multipart software=<SOFTWARE> system=<SYSTEM>.
#  Returns {ok, sysinfo:{os_name,build,display_version,release_id,edition,
#  registered_owner,install_date,computer_name}}. Defensive forensics on this server.
# =============================================================================
@app.post('/forensic/sysinfo')
def forensic_sysinfo():
    sw = request.files.get('software')
    if not sw or not sw.filename:
        return _err('need_software')
    sw_data = sw.read()
    if not sw_data:
        return _err('empty_software')
    sy = request.files.get('system')
    sy_data = sy.read() if (sy and sy.filename) else None
    if len(sw_data) > HIVE_MAX or (sy_data and len(sy_data) > HIVE_MAX):
        return _err('too_large', 413)
    app.logger.info("sysinfo in software=%d system=%s", len(sw_data), len(sy_data) if sy_data else 0)
    workdir = tempfile.mkdtemp(prefix='sysinfo_')
    try:
        from impacket import winregistry
        def _s(v):
            if isinstance(v, bytes):
                try: return v.decode('utf-16-le', errors='ignore').rstrip('\x00') or None
                except Exception: return None
            return v
        info = {}
        sw_p = os.path.join(workdir, 'SOFTWARE')
        with open(sw_p, 'wb') as fh: fh.write(sw_data)
        reg = winregistry.Registry(sw_p, isRemote=False)
        base = '\\Microsoft\\Windows NT\\CurrentVersion'
        for key, name in [('os_name', 'ProductName'), ('build', 'CurrentBuild'),
                          ('display_version', 'DisplayVersion'), ('release_id', 'ReleaseId'),
                          ('registered_owner', 'RegisteredOwner'), ('edition', 'EditionID')]:
            try:
                val = reg.getValue(base + '\\' + name)
                info[key] = _s(val[1]) if val else None
            except Exception:
                info[key] = None
        try:
            val = reg.getValue(base + '\\InstallDate')
            info['install_date'] = (val[1] if val else None)
        except Exception:
            info['install_date'] = None
        if sy_data:
            sy_p = os.path.join(workdir, 'SYSTEM')
            with open(sy_p, 'wb') as fh: fh.write(sy_data)
            try:
                sreg = winregistry.Registry(sy_p, isRemote=False)
                for cs in ('ControlSet001', 'ControlSet002', 'CurrentControlSet'):
                    try:
                        v = sreg.getValue('\\%s\\Control\\ComputerName\\ComputerName\\ComputerName' % cs)
                        if v and _s(v[1]):
                            info['computer_name'] = _s(v[1]); break
                    except Exception:
                        pass
            except Exception:
                pass
        return jsonify({'ok': True, 'sysinfo': info})
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("sysinfo failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /forensic/rdpcache  - RDP bitmap cache (.bmc) -> aggregated bitmap via bmc-tools.
#  Body: multipart with one or more .bmc files (any field names). Returns
#  {ok, tile_count, collage_b64(PNG of the aggregated tiles, <5MB)}.
# =============================================================================
@app.post('/forensic/rdpcache')
def forensic_rdpcache():
    files = []
    for _k in request.files:
        _f = request.files[_k]
        if _f and _f.filename:
            files.append((os.path.basename(_f.filename) or 'cache.bmc', _f.read()))
    if not files:
        return _err('need_bmc')
    workdir = tempfile.mkdtemp(prefix='rdpcache_')
    srcdir = os.path.join(workdir, 'src'); outdir = os.path.join(workdir, 'out')
    os.makedirs(srcdir); os.makedirs(outdir)
    try:
        for fn, data in files:
            if len(data) > HIVE_MAX:
                continue
            with open(os.path.join(srcdir, fn), 'wb') as fh:
                fh.write(data)
        app.logger.info("rdpcache in files=%d", len(files))
        import subprocess as _sp
        try:
            _sp.run(['python3', '/opt/bmc-tools.py', '-s', srcdir, '-d', outdir, '-b'],
                    capture_output=True, timeout=180)
        except Exception:
            pass
        bmps = []
        if os.path.isdir(outdir):
            bmps = sorted([os.path.join(outdir, f) for f in os.listdir(outdir)
                           if f.lower().endswith('.bmp')],
                          key=lambda p: os.path.getsize(p), reverse=True)
        collage_b64 = None
        if bmps:
            try:
                from PIL import Image
                import base64, io as _io
                im = Image.open(bmps[0]).convert('RGB')
                buf = _io.BytesIO(); im.save(buf, format='PNG', optimize=True)
                # full-res forensic mosaic delivered as a Telegram DOCUMENT (50MB limit)
                # -> keep up to 45MB, do NOT downscale (text fragments must stay readable)
                if buf.tell() < 45 * 1024 * 1024:
                    collage_b64 = base64.b64encode(buf.getvalue()).decode()
            except Exception:
                pass
        return jsonify({'ok': True, 'tile_count': len(bmps), 'collage_b64': collage_b64})
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("rdpcache failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.post('/forensic/ntlm')
def forensic_ntlm():
    sam_f = request.files.get('sam')
    sys_f = request.files.get('system')
    if not sam_f or not sys_f or not sam_f.filename or not sys_f.filename:
        return _err('need_sam_and_system')
    sam_data = sam_f.read()
    sys_data = sys_f.read()
    if not sam_data or not sys_data:
        return _err('empty_hive')
    if len(sam_data) > MAX_BYTES or len(sys_data) > MAX_BYTES:
        return _err('too_large', 413)
    app.logger.info("ntlm in sam=%d system=%d", len(sam_data), len(sys_data))
    workdir = tempfile.mkdtemp(prefix='ntlm_')
    try:
        sam_p = os.path.join(workdir, 'SAM')
        sys_p = os.path.join(workdir, 'SYSTEM')
        with open(sam_p, 'wb') as fh:
            fh.write(sam_data)
        with open(sys_p, 'wb') as fh:
            fh.write(sys_data)
        import io as _io
        import contextlib as _cl
        from impacket.examples.secretsdump import LocalOperations, SAMHashes
        local_ops = LocalOperations(sys_p)
        boot_key = local_ops.getBootKey()
        sam = SAMHashes(sam_p, boot_key, isRemote=False)
        buf = _io.StringIO()
        with _cl.redirect_stdout(buf):
            sam.dump()
        try:
            sam.finish()
        except Exception:
            pass
        accounts = []
        for line in buf.getvalue().splitlines():
            line = line.strip()
            parts = line.split(':')
            # format: username:rid:lmhash:nthash:::
            if len(parts) >= 4 and parts[1].isdigit():
                accounts.append({'username': parts[0], 'rid': int(parts[1]),
                                 'lm': parts[2], 'nt': parts[3]})
        app.logger.info("ntlm extracted accounts=%d", len(accounts))
        return jsonify({'ok': True, 'accounts': accounts})
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("ntlm failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.post('/pdf/unlock')
def pdf_unlock():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))

    # Password is consumed locally and never logged.
    password = request.form.get('password', '') or ''
    app.logger.info("unlock in sha256=%s size=%d", _sha256(data), len(data))

    workdir = tempfile.mkdtemp(prefix='unlock_')
    try:
        in_path = os.path.join(workdir, 'in.pdf')
        out_path = os.path.join(workdir, 'out.pdf')
        with open(in_path, 'wb') as fh:
            fh.write(data)
        try:
            # pikepdf opens with the user OR owner password; saving without an
            # `encryption=` argument writes a fully decrypted copy.
            with pikepdf.open(in_path, password=password) as pdf:
                pdf.save(out_path)
        except pikepdf.PasswordError:
            return _err('bad_password', 422)
        finally:
            password = ''  # drop secret from memory ASAP
        name = (os.path.splitext(fname)[0] or 'document') + '_decrypted.pdf'
        return _pdf_response(out_path, name)
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("unlock failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /pdf/translate — layout-preserving EN->UK PDF translation via pdf2zh
#  (PDFMathTranslate). Runs the pdf2zh CLI in-container as a subprocess; the
#  translator talks to the HOST gemma-2-9b-translate over the OpenAI API
#  (OPENAI_* env). The font is controlled SOLELY by NOTO_FONT_PATH (no --font
#  CLI flag exists in 1.9.11); we point it at LiberationSerif (Times-like) for
#  output closer to the original. A DFIR glossary + anti-hyphenation custom
#  prompt is passed via --prompt. Returns the produced *-mono.pdf.
#  Body: multipart file=<pdf>.
# =============================================================================
# =============================================================================
#  /v1/chat/completions + /v1/models — glossary-protecting OpenAI proxy.
#  pdf2zh (OPENAI_BASE_URL=http://localhost:8799/v1) calls THIS; we deterministically
#  protect DFIR glossary terms with [[N]] placeholders, forward to the real host
#  gemma (DFIR_GEMMA_URL), then restore the terms verbatim in the response. This is
#  the HARD glossary lock (same mechanism as the bot .txt path), independent of the
#  model obeying a prompt. Fail-open: any error -> forward/return unmodified.
# =============================================================================
import re as _re_gp
import urllib.request as _u_gp
_GP_GLOSS = [t.strip() for t in os.getenv('DFIR_PDF2ZH_GLOSSARY',
    'persistence,obfuscated,obfuscation,dropper,payload,beacon,beaconing,lateral movement,'
    'privilege escalation,credential dumping,exfiltration,command and control,'
    'living off the land,prefetch,amcache,shimcache,appcompatcache,lsass,mimikatz,'
    'powershell,sysmon,scheduled task,run key,firewall').split(',') if t.strip()]
_GP_GLOSS.sort(key=len, reverse=True)
_GP_PAT = _re_gp.compile(r'(?<!\w)(' + '|'.join(_re_gp.escape(t) for t in _GP_GLOSS) + r')(?!\w)', _re_gp.I) if _GP_GLOSS else None
_GP_BACKEND = os.getenv('DFIR_GEMMA_URL', 'http://192.168.134.1:1234/v1').rstrip('/')

@app.route('/v1/chat/completions', methods=['POST'])
def _glossary_proxy():
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}
    store = []
    try:
        if _GP_PAT is not None and isinstance(body.get('messages'), list):
            def _prot(m):
                store.append(m.group(0))
                return '[[%d]]' % (len(store) - 1)
            for msg in body['messages']:
                if isinstance(msg, dict) and msg.get('role') in ('user', 'system') and isinstance(msg.get('content'), str):
                    msg['content'] = _GP_PAT.sub(_prot, msg['content'])
            body['messages'].insert(0, {'role': 'system', 'content': 'Copy any token of the form [[N]] (e.g. [[0]], [[1]]) EXACTLY and unchanged. Never translate or alter such tokens.'})
    except Exception:
        store = []
    try:
        data = json.dumps(body).encode('utf-8')
        req = _u_gp.Request(_GP_BACKEND + '/chat/completions', data=data, headers={'Content-Type': 'application/json'})
        with _u_gp.urlopen(req, timeout=300) as r:
            resp = json.loads(r.read().decode('utf-8', errors='ignore'))
    except Exception as e:
        return jsonify({'error': {'message': 'proxy_backend_error: %s' % e}}), 502
    try:
        for ch in resp.get('choices', []):
            msg = ch.get('message', {})
            c = msg.get('content')
            if isinstance(c, str):
                for k in range(len(store) - 1, -1, -1):
                    c = c.replace('[[%d]]' % k, store[k])
                msg['content'] = c
    except Exception:
        pass
    return jsonify(resp)

@app.route('/v1/models', methods=['GET'])
def _glossary_proxy_models():
    try:
        with _u_gp.urlopen(_GP_BACKEND + '/models', timeout=20) as r:
            return Response(r.read(), content_type='application/json')
    except Exception as e:
        return jsonify({'error': {'message': str(e)}}), 502


# --- складання підсумкового PDF для /pdf/translate-sbs -----------------------
#  Ліворуч - зображення сторінки оригіналу (з водяним знаком, як є),
#  праворуч - переклад. Жодних зовнішніх посилань: файл самодостатній.
def _sbs_helvetica_share(pdf_path, password=''):
    """Частка символів, набраних Helvetica, у документі (0..1).

    Потрібна, щоб відрізнити ШТАМП поверх тексту від документа, де Helvetica -
    основний шрифт. Читається лише метрика шрифтів, вміст нікуди не передається.
    """
    try:
        doc = fitz.open(pdf_path)
        if doc.needs_pass:
            doc.authenticate(password or '')
        helv = total = 0
        for pno in range(min(doc.page_count, 12)):      # вистачає перших сторінок
            for blk in doc[pno].get_text('dict').get('blocks', []):
                if blk.get('type', 0) != 0:
                    continue
                for line in blk.get('lines', []):
                    for sp in line.get('spans', []):
                        n = len(sp.get('text') or '')
                        total += n
                        if (sp.get('font') or '').startswith('Helvetica'):
                            helv += n
        doc.close()
        return (helv / total) if total else 0.0
    except Exception as e:
        app.logger.warning('helvetica share: %s', str(e)[:120])
        return 0.0


def _sbs_make_watermark_rule(helv_share):
    """Повернути предикат «це водяний знак» під конкретний документ."""
    helv_is_stamp = helv_share < 0.5

    def _is_wm(span, line_rotated):
        if line_rotated:                                # діагональний напис - знак
            return True
        if helv_is_stamp and (span.get('font') or '').startswith('Helvetica'):
            return True
        return False
    return _is_wm


SBS_FONT = os.getenv('NOTO_FONT_PATH', '/app/GoNotoKurrent-Regular.ttf')


def _sbs_page_paragraphs(frag_path):
    """Витягти абзаци перекладу з нашого ж фрагмента HTML."""
    import html as _h
    import re as _re
    with open(frag_path, encoding='utf-8') as fh:
        raw = fh.read()
    m = _re.search(r"<div class=tr>(.*?)</div>", raw, _re.S)
    block = m.group(1) if m else ''
    paras = [_h.unescape(_re.sub(r'<[^>]+>', '', p)).strip()
             for p in _re.findall(r'<p>(.*?)</p>', block, _re.S)]
    return [p for p in paras if p]


def _sbs_build_pdf(book_dir, title):
    """Зібрати <book_dir>/<title>_ua.pdf. Повертає шлях або None."""
    import glob as _glob
    frags = sorted(_glob.glob(os.path.join(book_dir, 'frag', 'p*.html')))
    if not frags:
        return None
    out = fitz.open()
    W, H, M, GAP = 842.0, 595.0, 28.0, 14.0          # A4 альбомна, у пунктах
    half = (W - 2 * M - GAP) / 2
    for frag in frags:
        no = os.path.splitext(os.path.basename(frag))[0][1:]
        img = os.path.join(book_dir, 'img', 'p%s.png' % no)
        paras = _sbs_page_paragraphs(frag)
        first = True
        while True:
            page = out.new_page(width=W, height=H)
            left = fitz.Rect(M, M + 16, M + half, H - M)
            right = fitz.Rect(M + half + GAP, M + 16, W - M, H - M)
            page.insert_text((M, M + 8), 'Стор. %d — оригінал' % int(no),
                             fontsize=8, fontname='helv')
            page.insert_text((M + half + GAP, M + 8),
                             'Переклад%s' % ('' if first else ' (продовження)'),
                             fontsize=8, fontname='helv')
            if first and os.path.exists(img):
                try:
                    pix = fitz.Pixmap(img)
                    while pix.width > 1000:            # зайві пікселі лише важчають
                        pix = fitz.Pixmap(pix, 0) if pix.alpha else pix
                        pix.shrink(1)
                    page.insert_image(left, pixmap=pix, keep_proportion=True)
                except Exception as e:                 # сторінка без картинки - не привід падати
                    app.logger.warning('sbs pdf image %s: %s', img, str(e)[:120])
            if not paras:
                break
            # Вкласти стільки абзаців, скільки вміщується; решта - на наступну сторінку.
            size = 9.5
            take = len(paras)
            while take > 0:
                txt = '\n\n'.join(paras[:take])
                rc = page.insert_textbox(right, txt, fontsize=size,
                                         fontname='uk', fontfile=SBS_FONT,
                                         align=fitz.TEXT_ALIGN_LEFT)
                if rc >= 0:
                    break
                if size > 7.5 and take == len(paras):
                    size -= 0.5                        # спершу дрібніший шрифт
                    continue
                take -= 1
            paras = paras[max(take, 1):]
            first = False
            if not paras:
                break
    dst = os.path.join(book_dir, '%s_ua.pdf' % title)
    out.save(dst, deflate=True, garbage=3)
    out.close()
    return dst


@app.post('/pdf/translate-sbs')
def pdf_translate_sbs():
    """Side-by-side translation: original page image (left) + clean UK translation
    (right) as an HTML book, zipped. Uses the course engine (image render + watermark
    strip + local LLM). Reads better than pdf2zh layout reconstruction; the watermark
    stays visible on the original image but is stripped from the translated text."""
    import zipfile, io as _io, shutil as _shutil
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    if not fname.lower().endswith('.pdf'):
        return _err('unsupported_type', 415)
    password = request.form.get('password', '')
    app.logger.info("translate-sbs in sha256=%s size=%d name=%s",
                    _sha256(data), len(data), fname)
    workdir = tempfile.mkdtemp(prefix='sbs_', dir='/tmp')
    try:
        src = os.path.join(workdir, os.path.basename(fname))
        with open(src, 'wb') as fh:
            fh.write(data)
        import course_translate as eng
        eng.PDF_PASSWORD = password
        _share = _sbs_helvetica_share(src, password)
        eng.is_watermark = _sbs_make_watermark_rule(_share)
        app.logger.info('translate-sbs: частка Helvetica %.2f -> %s',
                        _share, 'штамп' if _share < 0.5 else 'основний шрифт')
        eng.OUT_DIR = os.path.join(workdir, 'out')
        eng.DECDIR = os.path.join(eng.OUT_DIR, '_decrypted')
        eng.BACKEND = 'openai'
        eng.ENDPOINT = os.getenv('LLM_ENDPOINT', 'http://192.168.100.1:1234').rstrip('/')
        eng.MODEL = os.getenv('SBS_MODEL', 'translate-9b')
        eng.WORKERS = int(os.getenv('SBS_WORKERS', '6'))
        os.makedirs(eng.OUT_DIR, exist_ok=True)
        try:
            eng.process_book(src)
        except Exception as _pe:
            import pikepdf as _pk
            if isinstance(_pe, _pk.PasswordError):
                return _err('bad_password', 422)
            app.logger.error('translate-sbs engine err: %s', str(_pe)[:300])
            return _err('process_failed', 500)
        book = os.path.splitext(os.path.basename(src))[0]
        book_dir = os.path.join(eng.OUT_DIR, book)
        if not os.path.isfile(os.path.join(book_dir, 'index.html')):
            return _err('process_failed', 500)
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(book_dir):
                rr = root.replace(chr(92), '/')
                if '/frag' in rr or '_decrypted' in rr:
                    continue  # intermediate fragments + decrypted original excluded (privacy)
                for fn in files:
                    fp = os.path.join(root, fn)
                    z.write(fp, os.path.relpath(fp, book_dir))
        buf.seek(0)
        out_bytes = buf.read()
        want = (request.form.get('format') or '').lower()
        if want != 'zip':
            try:
                pdf_path = _sbs_build_pdf(book_dir, book)
            except Exception as _be:
                app.logger.error('sbs pdf build err: %s', str(_be)[:300])
                pdf_path = None
            # 45 МБ - стеля вкладення в чаті; більший файл віддаємо архівом.
            if pdf_path and os.path.getsize(pdf_path) <= 45 * 1024 * 1024:
                with open(pdf_path, 'rb') as _fh:
                    pdf_bytes = _fh.read()
                app.logger.info("translate-sbs out pdf sha256=%s size=%d",
                                _sha256(pdf_bytes), len(pdf_bytes))
                return Response(pdf_bytes, mimetype='application/pdf',
                                headers={'Content-Disposition':
                                         'attachment; filename="%s_ua.pdf"' % book,
                                         'X-SBS-Format': 'pdf'})
            app.logger.warning('translate-sbs: PDF недоступний або завеликий, віддаю архів')
        app.logger.info("translate-sbs out sha256=%s size=%d", _sha256(out_bytes), len(out_bytes))
        return Response(out_bytes, mimetype='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="%s_ua.zip"' % book,
                                 'X-SBS-Format': 'zip'})
    except Exception as e:
        app.logger.error('translate-sbs err: %s', str(e)[:300])
        return _err('process_failed', 500)
    finally:
        try:
            _shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass


@app.post('/yara')
def yara_scan():
    """Scan an uploaded file against the local DFIR YARA ruleset. Offline, no net.
    Returns matched rules with severity/MITRE + the matched string identifiers."""
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    app.logger.info("yara in sha256=%s size=%d name=%s", _sha256(data), len(data), fname)
    try:
        import yara
        rules = yara.compile(filepath=os.getenv('YARA_RULES', '/app/dfir_rules.yar'))
        matches = rules.match(data=data, timeout=60)
        hits = []
        for m in matches:
            try:
                ids = sorted({(s.identifier if hasattr(s, 'identifier') else s[1]) for s in m.strings})
            except Exception:
                ids = []
            meta = getattr(m, 'meta', {}) or {}
            hits.append({'rule': m.rule, 'severity': meta.get('severity', ''),
                         'mitre': meta.get('mitre', ''), 'desc': meta.get('description', ''),
                         'matched': ids[:8]})
        return jsonify({'ok': True, 'file': fname, 'sha256': _sha256(data),
                        'clean': len(hits) == 0, 'matches': hits})
    except Exception as e:
        app.logger.error('yara err: %s', str(e)[:200])
        return _err('process_failed', 500)


@app.post('/pdf/translate')
def pdf_translate():
    import subprocess
    import glob
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    if not fname.lower().endswith('.pdf'):
        return _err('unsupported_type', 415)

    app.logger.info("pdf_translate in sha256=%s size=%d name=%s",
                    _sha256(data), len(data), fname)

    workdir = tempfile.mkdtemp(prefix='pdf2zh_', dir='/tmp')
    try:
        src = os.path.join(workdir, 'in.pdf')
        with open(src, 'wb') as fh:
            fh.write(data)
        outdir = os.path.join(workdir, 'out')
        os.makedirs(outdir, exist_ok=True)
        cmd = [os.getenv('DFIR_PDF2ZH_BIN', 'pdf2zh'), src,
               '-li', 'en', '-lo', 'uk',
               '-s', 'openai:' + os.getenv('OPENAI_MODEL', 'gemma-2-9b-translate'),
               '-t', os.getenv('DFIR_PDF2ZH_THREADS', '4'),
               '-o', outdir,
               '--prompt', os.getenv('DFIR_PDF2ZH_PROMPT', '/app/dfir_pdf2zh_prompt.txt'),
               '--skip-subset-fonts']   # keep full font => no glyph dropouts, fewer broken words
        env = dict(os.environ)  # carries OPENAI_*/NOTO_FONT_PATH/HOME into pdf2zh
        try:
            r = subprocess.run(cmd, cwd=workdir, env=env, capture_output=True,
                               timeout=int(os.getenv('DFIR_PDF2ZH_TIMEOUT', '1000')))
        except subprocess.TimeoutExpired:
            app.logger.error("pdf2zh timed out")
            return _err('process_failed', 504)
        if r.returncode != 0:
            app.logger.error('pdf2zh rc=%s err=%s', r.returncode,
                             r.stderr.decode('utf-8', 'ignore')[-800:])
            return _err('process_failed', 500)
        mono = glob.glob(os.path.join(outdir, '*-mono.pdf'))
        if not mono:
            app.logger.error('pdf2zh produced no -mono.pdf; outdir contents=%s',
                             os.listdir(outdir))
            return _err('process_failed', 500)
        name = (os.path.splitext(fname)[0] or 'document') + '_ua.pdf'
        return _pdf_response(mono[0], name)
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("pdf_translate failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /pdf/watermark — remove overlay AND burned-in raster watermarks
#  Deterministic + local. Four passes per page:
#    (1) delete Watermark/Stamp/FreeText annotations
#    (2) clean_contents() to drop orphaned overlay operators
#    (3) redact caller-supplied watermark TEXT in the vector content stream
#    (4) raster: OCR the rasterised page (Tesseract via PyMuPDF) to locate the
#        watermark text baked INTO an image, then blank ONLY those pixels
#        (apply_redactions images=PDF_REDACT_IMAGE_PIXELS) — real vector body
#        text and untouched image areas are preserved.
#  Requires a caller-supplied `text` for the raster pass (deterministic target);
#  without it only passes 1-2 run. If NOTHING was removed we return 422 with a
#  machine code instead of a misleading 'success' PDF. No numpy/OpenCV used
#  (absent in the image) — fitz + Tesseract only. An X-Watermark-Report header
#  on success summarises what was removed.
#  Body: multipart file=<pdf>, optional form field text=<watermark text>.
# =============================================================================
def _redact_raster_watermark(page, wm_text: str) -> int:
    """Detect watermark text burned into raster images on `page` and blank only
    those pixels. Returns count of redacted regions. Deterministic + local
    (Tesseract via PyMuPDF). If `wm_text` is empty we skip OCR (no reliable
    unsupervised target) and return 0 — the vector path may still act."""
    if not wm_text:
        return 0
    # Only bother if the page actually carries raster image content.
    try:
        if not page.get_images(full=True):
            return 0
    except Exception:
        return 0
    try:
        tp = page.get_textpage_ocr(language=OCR_DEFAULT_LANG.replace('ukr+eng', 'eng+ukr'),
                                   dpi=WM_OCR_DPI, full=True, tessdata=WM_TESSDATA)
    except Exception:
        return 0
    hits = []
    try:
        hits = page.search_for(wm_text, textpage=tp)
    except Exception:
        hits = []
    if not hits:
        return 0
    for rect in hits:
        # Pad slightly so anti-aliased edges of the watermark glyphs are covered.
        r = (rect + (-2, -2, 2, 2)) & page.rect
        page.add_redact_annot(r, fill=(1, 1, 1))
    page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_PIXELS,
                          graphics=fitz.PDF_REDACT_LINE_ART_NONE,
                          text=fitz.PDF_REDACT_TEXT_NONE)
    return len(hits)


@app.post('/pdf/watermark')
def pdf_watermark():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))

    wm_text = (request.form.get('text', '') or '').strip()
    app.logger.info("watermark in sha256=%s size=%d has_text=%s",
                    _sha256(data), len(data), bool(wm_text))

    workdir = tempfile.mkdtemp(prefix='wm_')
    try:
        out_path = os.path.join(workdir, 'out.pdf')
        n_annot = n_vector = n_raster = 0
        doc = fitz.open(stream=data, filetype='pdf')
        try:
            for page in doc:
                # (1) annotation / stamp watermarks -> delete outright
                annots = page.annots()
                if annots:
                    for annot in list(annots):
                        try:
                            kind = (annot.type[1] or '').lower()
                        except Exception:
                            kind = ''
                        if kind in ('watermark', 'stamp', 'freetext'):
                            page.delete_annot(annot)
                            n_annot += 1
                # (2) normalise / dedupe content streams (drops orphaned overlays)
                try:
                    page.clean_contents()
                except Exception:
                    pass
                # (3) vector watermark text -> redact in the content stream
                if wm_text:
                    vrects = []
                    try:
                        vrects = page.search_for(wm_text)
                    except Exception:
                        vrects = []
                    if vrects:
                        for rect in vrects:
                            page.add_redact_annot(rect)
                            n_vector += 1
                        try:
                            page.apply_redactions()
                        except Exception:
                            pass
                # (4) burned-in RASTER watermark -> OCR-locate + blank pixels
                try:
                    n_raster += _redact_raster_watermark(page, wm_text)
                except Exception as e:                       # noqa: BLE001
                    app.logger.error("raster watermark pass failed: %s", e)
            doc.save(out_path, garbage=4, deflate=True, clean=True)
        finally:
            doc.close()
        removed = n_annot + n_vector + n_raster
        report = (f"annotations={n_annot} vector_text={n_vector} "
                  f"raster_text={n_raster}")
        app.logger.info("watermark removed_items=%d (%s)", removed, report)
        # Honest result: if we changed nothing, do NOT pretend success.
        if removed == 0:
            code = 'no_watermark' if not wm_text else 'watermark_not_found'
            return _err(code, 422)
        name = (os.path.splitext(fname)[0] or 'document') + '_clean.pdf'
        resp = _pdf_response(out_path, name)
        resp.headers['X-Watermark-Report'] = report
        return resp
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("watermark failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)



# =============================================================================
#  /ocr — add an invisible searchable text layer to a scanned PDF/image
#  Body: multipart file=<pdf|image>, optional form field lang (e.g. "ukr+eng").
#  Always returns a PDF (ocrmypdf converts images to a single-page PDF).
# =============================================================================
@app.post('/ocr')
def ocr():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))

    lang = (request.form.get('lang') or OCR_DEFAULT_LANG).strip() or OCR_DEFAULT_LANG
    app.logger.info("ocr in sha256=%s size=%d lang=%s", _sha256(data), len(data), lang)

    ext = (os.path.splitext(fname)[1] or '').lower()
    workdir = tempfile.mkdtemp(prefix='ocr_')
    try:
        in_path = os.path.join(workdir, 'in' + (ext or '.pdf'))
        out_path = os.path.join(workdir, 'out.pdf')
        with open(in_path, 'wb') as fh:
            fh.write(data)

        # `image-to-pdf` lets us accept a raw photo; `skip_text` avoids errors on
        # pages that already have text; `deskew`/`clean` improve scan quality;
        # `--force-ocr` is intentionally NOT used (it rasterises real text).
        # output_type=pdf bypasses Ghostscript (GS 10.0.0 has a skip_text regression
        # that 500s every OCR request); keeps text-preserving OCR working.
        # GS 10.0.0 skip_text regression 500s every request; force_ocr re-OCRs all
        # pages (right for scanned docs) and avoids the broken skip-text Ghostscript path.
        kwargs = dict(language=lang, deskew=True, clean=True,
                      force_ocr=True, output_type="pdf", progress_bar=False, optimize=1)
        if ext in ('.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp', '.webp'):
            kwargs['image_dpi'] = 300
        try:
            ocrmypdf.ocr(in_path, out_path, **kwargs)
        except ocrmypdf.exceptions.PriorOcrFoundError:
            # already fully searchable -> just hand the original back as a PDF
            shutil.copyfile(in_path, out_path)
        name = (os.path.splitext(fname)[0] or 'document') + '_ocr.pdf'
        return _pdf_response(out_path, name)
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("ocr failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /meta — extract metadata as JSON (PDF info+XMP, DOCX core props, image EXIF)
#  Metadata is attacker-spoofable -> the bot must present it as *claimed*, not
#  ground truth. Returns {"ok": true, "kind": "...", "meta": {...}}.
# =============================================================================
def _multi_hashes(data: bytes) -> dict:
    return {'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()}


def _rational(v):
    try:
        if isinstance(v, (tuple, list)) and len(v) == 2:
            num, den = v
            return float(num) / float(den) if den else 0.0
        return float(v)
    except Exception:
        return None


def _gps_to_decimal(gps: dict):
    """Return (lat, lon) decimal degrees from a raw GPSInfo IFD, or None."""
    def _dms(values):
        try:
            d = _rational(values[0]); m = _rational(values[1]); s = _rational(values[2])
            if None in (d, m, s):
                return None
            return d + m / 60.0 + s / 3600.0
        except Exception:
            return None
    try:
        lat = _dms(gps.get(2)); lon = _dms(gps.get(4))
        if lat is None or lon is None:
            return None
        if str(gps.get(1, 'N')).upper().startswith('S'):
            lat = -lat
        if str(gps.get(3, 'E')).upper().startswith('W'):
            lon = -lon
        return (round(lat, 6), round(lon, 6))
    except Exception:
        return None


def _exif_to_dict(img: Image.Image) -> dict:
    """Clean EXIF -> readable dict. Scalars only; GPS decoded to decimal
    lat/long plus a maps URL. Dates normalised from 'YYYY:MM:DD' to ISO."""
    out = {}
    try:
        exif = img.getexif()
    except Exception:
        exif = None
    if not exif:
        return out
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, str(tag_id))
        if tag == 'GPSInfo':
            try:
                gps_ifd = exif.get_ifd(tag_id)
            except Exception:
                gps_ifd = value if isinstance(value, dict) else {}
            dec = _gps_to_decimal(gps_ifd or {})
            if dec:
                out['GPSLatitude'] = dec[0]
                out['GPSLongitude'] = dec[1]
                out['GPSMapURL'] = f'https://maps.google.com/?q={dec[0]},{dec[1]}'
            continue
        sval = str(value)
        if tag in ('DateTime', 'DateTimeOriginal', 'DateTimeDigitized') and len(sval) >= 10:
            sval = sval[:4] + '-' + sval[5:7] + '-' + sval[8:]
        out[tag] = sval
    return out


def _parse_pdf_date(s):
    """PDF date 'D:YYYYMMDDHHmmSS+ZZ'zz'' -> 'YYYY-MM-DD HH:MM:SS'. Best effort."""
    if not s:
        return None
    t = str(s)
    if t.startswith('D:'):
        t = t[2:]
    digits = t[:14]
    try:
        y = digits[0:4]; mo = digits[4:6] or '01'; d = digits[6:8] or '01'
        hh = digits[8:10] or '00'; mi = digits[10:12] or '00'; ss = digits[12:14] or '00'
        if len(y) == 4:
            return f'{y}-{mo}-{d} {hh}:{mi}:{ss}'.rstrip(' :')
    except Exception:
        pass
    return str(s)


_META_LABELS = {
    'author': 'Author', 'last_modified_by': 'Last modified by',
    'producer': 'Producer', 'creator': 'Creator', 'title': 'Title',
    'subject': 'Subject', 'keywords': 'Keywords', 'category': 'Category',
    'comments': 'Comments', 'created': 'Created', 'modified': 'Modified',
    'creationDate': 'Created', 'modDate': 'Modified', 'revision': 'Revision',
    'page_count': 'Pages', 'format': 'Format', 'encryption': 'Encryption',
    'xmp_present': 'XMP metadata present',
    'Make': 'Camera make', 'Model': 'Camera model', 'LensModel': 'Lens',
    'Software': 'Software', 'DateTimeOriginal': 'Taken (original)',
    'DateTime': 'File datetime', 'DateTimeDigitized': 'Digitized',
    'ExposureTime': 'Exposure', 'FNumber': 'Aperture', 'ISOSpeedRatings': 'ISO',
    'FocalLength': 'Focal length', 'Orientation': 'Orientation',
    'GPSLatitude': 'GPS latitude', 'GPSLongitude': 'GPS longitude',
    'GPSMapURL': 'Location (map)', '_format': 'Image format', '_size': 'Dimensions',
}

_META_ORDER = ['author', 'last_modified_by', 'producer', 'creator', 'Software',
               'title', 'subject', 'keywords', 'category', 'comments', 'revision',
               'created', 'modified', 'creationDate', 'modDate', 'page_count',
               'format', 'encryption', 'xmp_present',
               'Make', 'Model', 'LensModel', 'DateTimeOriginal', 'DateTime',
               'DateTimeDigitized', 'ExposureTime', 'FNumber', 'ISOSpeedRatings',
               'FocalLength', 'Orientation', '_format', '_size',
               'GPSLatitude', 'GPSLongitude', 'GPSMapURL']


def _render_meta_report(result: dict) -> str:
    """Deterministic, human-readable text report. No LLM, no network."""
    kind = result.get('kind') or 'unknown'
    meta = result.get('meta') or {}
    h = result.get('hashes') or {}
    head = {'pdf': 'PDF metadata', 'docx': 'DOCX metadata',
            'image': 'Image metadata (EXIF)'}.get(kind, f'Metadata ({kind})')
    lines = [head, f"File: {result.get('filename', '')}  ({result.get('size', 0)} bytes)",
             'NOTE: metadata is *claimed* by the file, not forensic proof.', '']
    seen = set()
    def _emit(key):
        if key in seen:
            return
        val = meta.get(key)
        if val in (None, '', {}, []):
            return
        if key == '_size' and isinstance(val, (list, tuple)) and len(val) == 2:
            val = f'{val[0]}x{val[1]} px'
        lines.append(f'  {_META_LABELS.get(key, key)}: {val}')
        seen.add(key)
    for key in _META_ORDER:
        _emit(key)
    for key in meta:
        _emit(key)
    if h:
        lines += ['', 'Hashes:',
                  f"  MD5:    {h.get('md5', '')}",
                  f"  SHA1:   {h.get('sha1', '')}",
                  f"  SHA256: {h.get('sha256', '')}"]
    return '\n'.join(lines)


@app.post('/malware-static')
def malware_static():
    """STATIC-ONLY malware triage (never executes the file): entropy (packing),
    file type by magic, suspicious strings (URLs/IPs/APIs), and PE analysis
    (imports, section entropy, compile time). Safe: pure read of bytes."""
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    import math, re as _re
    from collections import Counter
    out = {'ok': True, 'filename': fname, 'sha256': _sha256(data), 'size': len(data)}
    if data:
        ln = len(data); cnt = Counter(data)
        ent = -sum((c / ln) * math.log2(c / ln) for c in cnt.values())
        out['entropy'] = round(ent, 2)
        out['packed_likely'] = ent > 7.2
    is_pe = data[:2] == b'MZ'
    out['type'] = ('PE/EXE/DLL' if is_pe else 'PDF' if data[:4] == b'%PDF'
                   else 'ZIP/Office/JAR' if data[:2] == b'PK' else 'other')
    text = b'\n'.join(_re.findall(rb'[\x20-\x7e]{5,}', data)).decode('latin-1', 'ignore')
    urls = list(dict.fromkeys(_re.findall(r'https?://[^\s"\'<>]{4,}', text)))[:20]
    ips = list(dict.fromkeys(ip for ip in _re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text)
                            if not ip.startswith(('10.', '192.168.', '127.', '0.', '169.254.'))))[:20]
    _API = ('VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 'WriteProcessMemory',
            'LoadLibrary', 'GetProcAddress', 'WinExec', 'ShellExecute', 'URLDownloadToFile',
            'RegSetValue', 'CreateProcess', 'SetWindowsHookEx', 'CryptEncrypt', 'InternetOpen',
            'InternetConnect', 'HttpSendRequest', 'IsDebuggerPresent', 'CreateService',
            'AdjustTokenPrivileges', 'OpenProcess', 'NtUnmapViewOfSection')
    susp = sorted({a for a in _API if a in text})
    out['iocs'] = {'urls': urls, 'ips': ips, 'suspicious_apis': susp}
    if is_pe:
        try:
            import pefile, datetime
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            imps = []
            for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])[:60]:
                for imp in entry.imports[:80]:
                    if imp.name:
                        imps.append(imp.name.decode('latin-1', 'ignore'))
            ts = int(getattr(pe.FILE_HEADER, 'TimeDateStamp', 0) or 0)
            out['pe'] = {
                'compile_time': (datetime.datetime.utcfromtimestamp(ts).isoformat()
                                 if 0 < ts < 4102444800 else 'invalid/faked'),
                'is_dll': bool(pe.is_dll()), 'is_exe': bool(pe.is_exe()),
                'sections': [{'name': sec.Name.decode('latin-1', 'ignore').rstrip('\x00'),
                              'entropy': round(sec.get_entropy(), 2)} for sec in pe.sections][:12],
                'imported_dangerous': sorted({a for a in _API if a in imps}),
            }
        except Exception as e:
            out['pe'] = {'error': str(e)[:120]}
    # verdict heuristic (static only; YARA verdict comes from /yara separately)
    score = len(susp) + (2 if out.get('packed_likely') else 0) + len(urls[:5]) +         (2 if is_pe and out.get('pe', {}).get('imported_dangerous') else 0)
    out['verdict'] = ('високий ризик' if score >= 6 else 'підозріло' if score >= 3 else 'ознак мало')
    return jsonify(out)


@app.post('/meta')
def meta():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))

    app.logger.info("meta in sha256=%s size=%d name=%s", _sha256(data), len(data), fname)
    ext = (os.path.splitext(fname)[1] or '').lower()
    workdir = tempfile.mkdtemp(prefix='meta_')
    try:
        _hashes = _multi_hashes(data)
        result = {'ok': True, 'filename': fname, 'sha256': _hashes['sha256'],
                  'hashes': _hashes, 'size': len(data), 'kind': None, 'meta': {}}

        if ext == '.pdf':
            result['kind'] = 'pdf'
            doc = fitz.open(stream=data, filetype='pdf')
            try:
                _m = {k: v for k, v in (doc.metadata or {}).items() if v}
                for _dk in ('creationDate', 'modDate'):
                    if _m.get(_dk):
                        _m[_dk] = _parse_pdf_date(_m[_dk])
                _m['page_count'] = doc.page_count
                xml = doc.xref_xml_metadata() if hasattr(doc, 'xref_xml_metadata') else ''
                if xml:
                    _m['xmp_present'] = True
                result['meta'] = _m
            finally:
                doc.close()

        elif ext in ('.docx',):
            import docx  # python-docx
            result['kind'] = 'docx'
            in_path = os.path.join(workdir, 'in.docx')
            with open(in_path, 'wb') as fh:
                fh.write(data)
            cp = docx.Document(in_path).core_properties
            result['meta'] = {
                'author': cp.author, 'last_modified_by': cp.last_modified_by,
                'created': str(cp.created) if cp.created else None,
                'modified': str(cp.modified) if cp.modified else None,
                'revision': cp.revision, 'title': cp.title,
                'subject': cp.subject, 'category': cp.category,
                'comments': cp.comments, 'keywords': cp.keywords,
            }

        elif ext in ('.png', '.jpg', '.jpeg', '.tif', '.tiff', '.bmp', '.webp', '.heic'):
            result['kind'] = 'image'
            in_path = os.path.join(workdir, 'in' + ext)
            with open(in_path, 'wb') as fh:
                fh.write(data)
            with Image.open(in_path) as img:
                result['meta'] = _exif_to_dict(img)
                result['meta']['_format'] = img.format
                result['meta']['_size'] = list(img.size)
        else:
            result['kind'] = 'unsupported'
            result['meta'] = {}

        result['report'] = _render_meta_report(result)
        app.logger.info("meta kind=%s keys=%d", result['kind'], len(result['meta']))
        return jsonify(result)
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("meta failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /translate/extract — EXTRACT ONLY (translation is done by the BOT's LLM)
#  Pulls plain text out of PDF/DOCX/TXT so the bot can chunk + translate it via
#  build_chat_payload(). The sidecar performs NO translation (see module header).
#  Returns {"ok": true, "kind": "...", "text": "...", "chars": N, "truncated": bool}
# =============================================================================
EXTRACT_CHAR_CAP = int(os.getenv('SIDECAR_EXTRACT_CHAR_CAP', str(400_000)))


@app.post('/translate/extract')
def translate_extract():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))

    app.logger.info("extract in sha256=%s size=%d name=%s", _sha256(data), len(data), fname)
    ext = (os.path.splitext(fname)[1] or '').lower()
    workdir = tempfile.mkdtemp(prefix='extract_')
    try:
        text = ''
        kind = 'unsupported'
        if ext == '.pdf':
            kind = 'pdf'
            doc = fitz.open(stream=data, filetype='pdf')
            try:
                text = '\n'.join(page.get_text('text') for page in doc)
            finally:
                doc.close()
        elif ext == '.docx':
            kind = 'docx'
            import docx
            in_path = os.path.join(workdir, 'in.docx')
            with open(in_path, 'wb') as fh:
                fh.write(data)
            d = docx.Document(in_path)
            text = '\n'.join(p.text for p in d.paragraphs)
        elif ext in ('.txt', '.md', '.csv', '.log'):
            kind = 'text'
            text = data.decode('utf-8', errors='replace')
        else:
            return _err('unsupported_type', 415)

        truncated = len(text) > EXTRACT_CHAR_CAP
        if truncated:
            text = text[:EXTRACT_CHAR_CAP]
        app.logger.info("extract kind=%s chars=%d truncated=%s", kind, len(text), truncated)
        return jsonify({'ok': True, 'kind': kind, 'text': text,
                        'chars': len(text), 'truncated': truncated})
    except Exception as e:                                   # noqa: BLE001
        app.logger.error("extract failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /bookidx/index — OFFLINE Study exam index generator.
#  Body: multipart file=<pdf> [password=<str>] [book_label=<str>] [page_offset=<int>]
#  Runs the local bookidx pipeline (regex + LOCAL LLM only; content never leaves the
#  host) and returns a ZIP of index.xlsx/csv/docx + review + run_report. Encrypted
#  PDFs handled exactly like /pdf/unlock (bad_password -> bot asks via Telegram).
# =============================================================================
@app.post('/bookidx/index')
def bookidx_index():
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    password = request.form.get('password', '') or ''
    book_label = request.form.get('book_label') or (os.path.splitext(fname)[0] or 'Book 1')
    try:
        page_offset = int(request.form.get('page_offset', '0') or '0')
    except ValueError:
        page_offset = 0
    app.logger.info("bookidx in sha256=%s size=%d", _sha256(data), len(data))
    workdir = tempfile.mkdtemp(prefix='bookidx_')
    try:
        in_path = os.path.join(workdir, 'in.pdf')
        dec_path = os.path.join(workdir, 'dec.pdf')
        with open(in_path, 'wb') as fh:
            fh.write(data)
        try:
            import pikepdf
            with pikepdf.open(in_path, password=password) as pdf:
                pdf.save(dec_path)
        except pikepdf.PasswordError:
            return _err('bad_password', 422)
        except Exception:
            dec_path = in_path  # not encrypted -> use original
        finally:
            password = ''
        out_dir = os.path.join(workdir, 'out')
        base = os.getenv('DFIR_GEMMA_URL', 'http://192.168.134.1:1234/v1')
        model = os.getenv('BOOKIDX_MODEL', 'gpt-small-20b')
        from bookidx.src.bot_api import run_single_pdf
        res = run_single_pdf(dec_path, out_dir, book_label=book_label,
                             page_offset=page_offset, llm_base_url=base, llm_model=model)
        import zipfile
        zip_path = os.path.join(workdir, 'bookidx_index.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for k in ('xlsx', 'csv', 'cheatsheet', 'cheatsheet_uk_csv',
                      'cheatsheet_uk_docx', 'docx', 'review', 'report'):
                p = res.get(k)
                if p and os.path.exists(p):
                    z.write(p, os.path.basename(p))
        with open(zip_path, 'rb') as fh:
            out_bytes = fh.read()
        app.logger.info("bookidx out entries=%s flagged=%s pages=%s zip=%d",
                        res.get('entries'), res.get('flagged'), res.get('pages'), len(out_bytes))
        resp = Response(out_bytes, mimetype='application/zip')
        resp.headers['Content-Disposition'] = 'attachment; filename="bookidx_index.zip"'
        resp.headers['X-Bookidx-Entries'] = str(res.get('entries', 0))
        resp.headers['X-Bookidx-Flagged'] = str(res.get('flagged', 0))
        return resp
    except Exception as e:
        app.logger.error("bookidx failed: %s", e)
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# =============================================================================
#  /audio-translate-ua  — English audio -> spoken-Ukrainian MP3
# -----------------------------------------------------------------------------
#  Additive pipeline that REUSES existing host GPU infra (nothing new leaves the
#  VM/host network):
#    1. host GPU Whisper large-v3 on :8771 /asr  -> English transcript
#       (same service the bot's transcribe / audio_clean tools already use)
#    2. host translate-9b (gemma-2-9b) on :1234 -> Ukrainian text, chunked
#       (same LLM the bot's document translation already uses)
#    3. Piper (uk_UA-ukrainian_tts-medium, grapheme voice, 22050 Hz) -> WAV
#    4. ffmpeg -> MP3 (22050 Hz mono, 64 kbps)
#  Returns JSON shaped like the whisper /enhance reply the bot already handles:
#    {ok, en_text, ua_text, audio_b64, audio_fmt:"mp3", dur_s, voice}
#  Forensic hygiene: private tempdir, always removed; only sizes/hashes logged.
# =============================================================================
_WHISPER_URL   = os.getenv('DFIR_WHISPER_URL', 'http://192.168.134.1:8771').rstrip('/')
_ATR_LLM_BASE  = os.getenv('DFIR_GEMMA_URL', 'http://192.168.134.1:1234/v1').rstrip('/')
_ATR_LLM_MODEL = os.getenv('AUDIO_TR_MODEL', 'translate-9b')
_PIPER_VOICE   = os.getenv('PIPER_UK_VOICE', '/app/voices/uk_UA-ukrainian_tts-medium.onnx')
_ATR_CHUNK     = int(os.getenv('AUDIO_TR_CHUNK_CHARS', '1400'))
# --- long-lecture (memory-bounded) audio-translate settings (2026-07-05) ------
#  Segment the input on disk (7-min chunks), process one segment at a time, and
#  write the final MP3 straight into the shared results dir (served by nginx),
#  so we NEVER hold the whole audio / transcript / TTS output in RAM at once.
_ATR_SEG_SECONDS   = int(os.getenv('AUDIO_TR_SEG_SECONDS', '420'))       # 7-min segments
_ATR_RESULTS_DIR   = os.getenv('DFIR_AUDIO_RESULTS_DIR', '/audio_results')
_ATR_UPLOAD_BASE   = os.getenv('DFIR_UPLOAD_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080').rstrip('/')
_ATR_B64_MAX       = int(os.getenv('AUDIO_TR_B64_MAX', str(20 * 1024 * 1024)))  # inline b64 only for small outputs
_ATR_TEXT_TG_MAX   = int(os.getenv('AUDIO_TR_TEXT_TG_MAX', '12000'))     # cap transcript chars returned inline
# Piper/onnxruntime allocates memory proportional to the *single* text it is
# handed (a 6 k-char call spikes to ~11 GB and the arena never shrinks). So the
# TTS text is synthesised in small sentence-aware sub-chunks: ~350 chars peaks
# at ~0.6 GB and is stitched back together on disk. NEVER raise this blindly.
_ATR_TTS_CHUNK     = int(os.getenv('AUDIO_TR_TTS_CHUNK_CHARS', '350'))

_piper_voice_obj = None          # lazily loaded once per worker (onnx load is slow)
_piper_lock = None

# The uk_UA-ukrainian_tts-medium voice is a *grapheme* model: its phoneme_id_map
# contains ONLY lowercase Ukrainian letters + punctuation (49 keys, no digits,
# no uppercase, no Latin). Text must therefore be lowercased before synthesis,
# and digits must be spelled out or they are silently dropped. We instruct the
# LLM to spell numbers out; this map is a last-resort safety net so a stray digit
# is at least vocalised instead of skipped.
_UK_DIGITS = {'0': ' нуль ', '1': ' один ', '2': ' два ', '3': ' три ',
              '4': ' чотири ', '5': " п'ять ", '6': ' шість ', '7': ' сім ',
              '8': ' вісім ', '9': " дев'ять "}


def _atr_whisper_en(audio_bytes, fname, language, task):
    """POST audio to the host GPU Whisper (:8771 /asr). Returns (text, info dict).
    Uses a hand-built multipart body (stdlib) so we do not add a dependency."""
    import urllib.request as _u
    boundary = 'atr' + hashlib.sha256(os.urandom(16)).hexdigest()[:26]

    def _part(name, value, fn=None, ct=None):
        h = '--%s\r\nContent-Disposition: form-data; name="%s"' % (boundary, name)
        if fn:
            h += '; filename="%s"' % fn
        h += '\r\n'
        if ct:
            h += 'Content-Type: %s\r\n' % ct
        h += '\r\n'
        b = value if isinstance(value, bytes) else str(value).encode('utf-8')
        return h.encode('utf-8') + b + b'\r\n'

    body  = _part('file', audio_bytes, fn=(fname or 'audio'), ct='application/octet-stream')
    body += _part('language', language or 'en')
    body += _part('task', task or 'transcribe')
    body += ('--%s--\r\n' % boundary).encode('utf-8')
    req = _u.Request(_WHISPER_URL + '/asr', data=body,
                     headers={'Content-Type': 'multipart/form-data; boundary=%s' % boundary})
    with _u.urlopen(req, timeout=900) as r:
        d = json.loads(r.read().decode('utf-8', 'ignore'))
    if not d.get('ok'):
        raise RuntimeError('whisper_failed:' + str(d.get('error'))[:120])
    return (d.get('text') or '').strip(), d


def _atr_chunk_text(text, limit):
    """Split on sentence boundaries into <=limit-char chunks (keeps sentences whole)."""
    import re as _re
    text = (text or '').strip()
    if not text:
        return []
    sents = _re.split(r'(?<=[.!?…])\s+', text)
    chunks, cur = [], ''
    for s in sents:
        if len(cur) + len(s) + 1 > limit and cur:
            chunks.append(cur.strip())
            cur = ''
        if len(s) > limit:                       # a single monster sentence
            if cur:
                chunks.append(cur.strip()); cur = ''
            for i in range(0, len(s), limit):
                chunks.append(s[i:i + limit].strip())
            continue
        cur += s + ' '
    if cur.strip():
        chunks.append(cur.strip())
    return chunks


def _atr_translate_uk(en_text):
    """EN -> UK via the host translate-9b (OpenAI chat API), chunked for context.
    Instructs the model to output ONLY Ukrainian and to SPELL OUT numbers (the TTS
    voice cannot vocalise digits)."""
    import urllib.request as _u
    sysmsg = ("You are a professional English->Ukrainian translator. Translate the "
              "user's English text into natural, fluent Ukrainian. Write ALL numbers, "
              "dates and abbreviations as Ukrainian WORDS (no digits, no Latin "
              "letters). Output ONLY the Ukrainian translation — no notes, no "
              "transliteration, no English, no quotation marks.")
    out = []
    for ch in _atr_chunk_text(en_text, _ATR_CHUNK):
        payload = {'model': _ATR_LLM_MODEL,
                   'messages': [{'role': 'system', 'content': sysmsg},
                                {'role': 'user', 'content': ch}],
                   'temperature': 0.2, 'max_tokens': 2048, 'stream': False}
        data = json.dumps(payload).encode('utf-8')
        req = _u.Request(_ATR_LLM_BASE + '/chat/completions', data=data,
                         headers={'Content-Type': 'application/json'})
        with _u.urlopen(req, timeout=300) as r:
            resp = json.loads(r.read().decode('utf-8', 'ignore'))
        msg = ((resp.get('choices') or [{}])[0].get('message') or {}).get('content') or ''
        if msg.strip():
            out.append(msg.strip())
    return '\n'.join(out).strip()


def _atr_get_voice():
    global _piper_voice_obj, _piper_lock
    if _piper_lock is None:
        import threading
        _piper_lock = threading.Lock()
    if _piper_voice_obj is None:
        with _piper_lock:
            if _piper_voice_obj is None:
                from piper import PiperVoice
                _piper_voice_obj = PiperVoice.load(_PIPER_VOICE)
    return _piper_voice_obj


def _atr_prep_for_tts(uk_text):
    """Lowercase + vocalise stray digits so the grapheme voice does not drop them."""
    t = (uk_text or '').lower()
    return ''.join(_UK_DIGITS.get(c, c) for c in t)


def _atr_synth_mp3(uk_text, workdir):
    """UK text -> WAV (Piper, handles multi-sentence internally) -> MP3 (ffmpeg)."""
    import wave
    import subprocess as _sp
    voice = _atr_get_voice()
    wav_path = os.path.join(workdir, 'ua.wav')
    mp3_path = os.path.join(workdir, 'ua.mp3')
    tts_text = _atr_prep_for_tts(uk_text)
    with wave.open(wav_path, 'wb') as wf:
        voice.synthesize_wav(tts_text, wf)
    # WAV -> MP3, 22050 Hz mono 64k (small, voice-grade, plays inline in Telegram)
    _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
             '-i', wav_path, '-ar', '22050', '-ac', '1', '-b:a', '64k', mp3_path],
            check=True)
    return mp3_path


# ---------------------------------------------------------------------------
#  Memory-bounded long-lecture helpers (segment on disk, one at a time)
# ---------------------------------------------------------------------------
def _atr_ffprobe_dur(path):
    """Return media duration in seconds (float) via ffprobe, or 0.0 on failure."""
    import subprocess as _sp
    try:
        out = _sp.run(['ffprobe', '-v', 'error', '-show_entries', 'format=duration',
                       '-of', 'default=noprint_wrappers=1:nokey=1', path],
                      capture_output=True, text=True, timeout=120)
        return float((out.stdout or '0').strip() or 0)
    except Exception:
        return 0.0


def _atr_segment_input(in_path, workdir):
    """Decode the whole input to 16 kHz mono WAV *segments* on disk (constant memory).
    16 kHz mono is exactly what Whisper wants and keeps each segment small.
    Returns a sorted list of segment WAV paths."""
    import subprocess as _sp
    import glob as _glob
    seg_dir = os.path.join(workdir, 'seg')
    os.makedirs(seg_dir, exist_ok=True)
    pattern = os.path.join(seg_dir, 'in_%04d.wav')
    _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
             '-i', in_path, '-vn', '-ar', '16000', '-ac', '1',
             '-f', 'segment', '-segment_time', str(_ATR_SEG_SECONDS),
             pattern], check=True)
    return sorted(_glob.glob(os.path.join(seg_dir, 'in_*.wav')))


def _atr_synth_seg_mp3(uk_text, out_mp3, workdir):
    """UK text of ONE segment -> MP3 (22050 mono 64k) on disk, MEMORY-BOUNDED.

    Piper is fed the text in small sentence-aware sub-chunks (_ATR_TTS_CHUNK
    chars). A single big call makes onnxruntime allocate GBs (and never release
    the arena); small calls keep peak RSS at a few hundred MB. Each sub-chunk is
    written to its own tiny WAV, then all sub-WAVs are concatenated on disk into
    one segment MP3. All intermediates are deleted immediately."""
    import wave
    import subprocess as _sp
    voice = _atr_get_voice()
    sub_dir = out_mp3 + '_sub'
    os.makedirs(sub_dir, exist_ok=True)
    sub_wavs = []
    try:
        for i, sub in enumerate(_atr_chunk_text(uk_text, _ATR_TTS_CHUNK)):
            tts_text = _atr_prep_for_tts(sub)
            if not tts_text.strip():
                continue
            w = os.path.join(sub_dir, 's%04d.wav' % i)
            with wave.open(w, 'wb') as wf:
                voice.synthesize_wav(tts_text, wf)
            sub_wavs.append(w)
        if not sub_wavs:
            raise RuntimeError('tts_empty')
        if len(sub_wavs) == 1:
            _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
                     '-i', sub_wavs[0], '-ar', '22050', '-ac', '1', '-b:a', '64k', out_mp3],
                    check=True)
        else:
            list_path = os.path.join(sub_dir, 'list.txt')
            with open(list_path, 'w', encoding='utf-8') as fh:
                for w in sub_wavs:
                    fh.write("file '%s'\n" % w.replace("'", "'\\''"))
            _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
                     '-f', 'concat', '-safe', '0', '-i', list_path,
                     '-ar', '22050', '-ac', '1', '-b:a', '64k', out_mp3],
                    check=True)
        return out_mp3
    finally:
        shutil.rmtree(sub_dir, ignore_errors=True)


def _atr_concat_mp3(seg_mp3_list, out_mp3, workdir):
    """Concatenate per-segment MP3s on disk via the ffmpeg concat demuxer.
    Re-encodes to one clean CBR stream (gapless, uniform headers) without ever
    loading all segments into a single Python bytes object."""
    import subprocess as _sp
    if not seg_mp3_list:
        raise RuntimeError('no_segments')
    if len(seg_mp3_list) == 1:
        shutil.copyfile(seg_mp3_list[0], out_mp3)
        return out_mp3
    list_path = os.path.join(workdir, 'concat.txt')
    with open(list_path, 'w', encoding='utf-8') as fh:
        for p in seg_mp3_list:
            fh.write("file '%s'\n" % p.replace("'", "'\\''"))
    _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
             '-f', 'concat', '-safe', '0', '-i', list_path,
             '-ar', '22050', '-ac', '1', '-b:a', '64k', out_mp3],
            check=True)
    return out_mp3



# Cyrillic (UA+RU) -> ASCII transliteration for result filenames. Prevents the
# Telegram-link breakage: the old sanitizer mapped every Cyrillic char to '_',
# producing runs like '____________' that broke Telegram URL auto-linkification
# (browser opened a truncated URL -> 404). Transliteration keeps names readable
# AND ASCII-safe with no underscore runs.
_TRANSLIT_MAP = {
    'а': 'a', 'б': 'b', 'в': 'v', 'г': 'h', 'ґ': 'g', 'д': 'd', 'е': 'e', 'є': 'ie',
    'ж': 'zh', 'з': 'z', 'и': 'y', 'і': 'i', 'ї': 'i', 'й': 'i', 'к': 'k', 'л': 'l',
    'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u',
    'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch', 'ь': '',
    'ю': 'iu', 'я': 'ia', 'ы': 'y', 'э': 'e', 'ъ': '', 'ё': 'e',
}


def _translit_fname(base, fallback='file', cap=50):
    """Cyrillic->ASCII transliterate, then keep only URL/Telegram-safe chars and
    collapse '_' runs. Returns a clean, link-safe stem."""
    import re as _rr
    s = (base or '').lower()
    s = ''.join(_TRANSLIT_MAP.get(c, c) for c in s)
    s = _rr.sub(r'[^a-z0-9.-]+', '_', s)
    s = _rr.sub(r'_{2,}', '_', s).strip('._-')[:cap]
    return s or fallback


def _atr_save_result_file(src_path, base, ext):
    """Move a produced file into the shared results dir under a uuid-prefixed name.
    Returns (public_url, filename, dest_path) or (None, None, None) if unavailable.
    Best-effort: never raises (link delivery is additive)."""
    import re as _re
    import uuid as _uuid
    try:
        if not os.path.isdir(_ATR_RESULTS_DIR):
            app.logger.warning('atr results dir missing: %s', _ATR_RESULTS_DIR)
            return None, None, None
        safe = _translit_fname(base, fallback='audio')
        fname = '%s_%s_ua.%s' % (_uuid.uuid4().hex, safe, ext)
        dest = os.path.join(_ATR_RESULTS_DIR, fname)
        tmp = os.path.join(_ATR_RESULTS_DIR, '.' + fname + '.part')
        shutil.copyfile(src_path, tmp)
        os.replace(tmp, dest)
        url = _ATR_UPLOAD_BASE + '/audio/' + fname
        app.logger.info('atr result saved: %s (%d bytes) -> %s',
                        fname, os.path.getsize(dest), url)
        return url, fname, dest
    except Exception as e:
        app.logger.warning('atr result save failed: %s', repr(e)[:200])
        return None, None, None


def _atr_save_text_result(text, base, suffix):
    """Write a transcript .txt into the shared results dir; return url or None."""
    import re as _re
    import uuid as _uuid
    try:
        if not text or not os.path.isdir(_ATR_RESULTS_DIR):
            return None
        safe = _translit_fname(base, fallback='audio')
        fname = '%s_%s_%s.txt' % (_uuid.uuid4().hex, safe, suffix)
        dest = os.path.join(_ATR_RESULTS_DIR, fname)
        tmp = dest + '.part'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(text)
        os.replace(tmp, dest)
        return _ATR_UPLOAD_BASE + '/audio/' + fname
    except Exception as e:
        app.logger.warning('atr text save failed: %s', repr(e)[:160])
        return None


# =============================================================================
#  /book-to-mp3 — EPUB/PDF/FB2/DOCX/TXT book -> Ukrainian-voice MP3 audiobook.
#  Reuses the memory-bounded Piper TTS segment pipeline from /audio-translate-ua.
#  Body: multipart file=<book> [progress_file=<name in /audio_results>]
# =============================================================================
_BOOK_CHAR_CAP = int(os.getenv('BOOK_CHAR_CAP', '2500000'))    # whole novels -> one glued file + link
_BOOK_TTS_URL = os.getenv('DFIR_TTS_UA_URL', 'http://192.168.134.1:8774').rstrip('/')
_BOOK_TTS_TIMEOUT = int(os.getenv('DFIR_TTS_UA_TIMEOUT', '900'))


def _book_synth_seg(text, out_mp3, workdir):
    """One book segment -> MP3. Prefers the host StyleTTS2-ukrainian service
    (natural intonation, GPU, :8774); falls back to local Piper when the host
    TTS is down so the tool never hard-fails."""
    import urllib.request as _u
    import subprocess as _sp
    try:
        body = json.dumps({'text': text, 'verbalize': 'auto'}).encode('utf-8')
        req = _u.Request(_BOOK_TTS_URL + '/tts', data=body,
                         headers={'Content-Type': 'application/json'}, method='POST')
        with _u.urlopen(req, timeout=_BOOK_TTS_TIMEOUT) as r:
            wav_bytes = r.read()
        if wav_bytes[:4] == b'RIFF':
            wav_path = out_mp3 + '.src.wav'
            with open(wav_path, 'wb') as fh:
                fh.write(wav_bytes)
            del wav_bytes
            _sp.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
                     '-i', wav_path, '-ar', '22050', '-ac', '1', '-b:a', '64k', out_mp3],
                    check=True)
            try:
                os.unlink(wav_path)
            except Exception:
                pass
            return out_mp3
        app.logger.warning('host TTS returned non-WAV -> piper fallback')
    except Exception as e:
        app.logger.warning('host TTS unavailable (%s) -> piper fallback', str(e)[:140])
    return _atr_synth_seg_mp3(text, out_mp3, workdir)

_BOOK_SEG_CHARS = int(os.getenv('BOOK_SEG_CHARS', '4000'))


def _epub_extract_text(data):
    """EPUB -> plain text, chapters in spine order (stdlib only: zip + regex)."""
    import zipfile, re as _re, html as _html
    from io import BytesIO
    from urllib.parse import unquote
    zf = zipfile.ZipFile(BytesIO(data))
    names = zf.namelist()
    order = []
    try:
        cont = zf.read('META-INF/container.xml').decode('utf-8', 'replace')
        opf_path = _re.search(r'full-path="([^"]+)"', cont).group(1)
        opf = zf.read(opf_path).decode('utf-8', 'replace')
        base = opf_path.rsplit('/', 1)[0] + '/' if '/' in opf_path else ''
        man = {}
        for tag in _re.findall(r'<item\b[^>]*>', opf):
            mid = _re.search(r'\bid="([^"]+)"', tag)
            href = _re.search(r'\bhref="([^"]+)"', tag)
            if mid and href:
                man[mid.group(1)] = unquote(href.group(1))
        for idr in _re.findall(r'<itemref[^>]+idref="([^"]+)"', opf):
            href = man.get(idr)
            if href and _re.search(r'\.x?html?($|\?)', href.lower()):
                order.append(base + href)
    except Exception:
        order = []
    if not order:
        order = [n for n in names if n.lower().endswith(('.xhtml', '.html', '.htm'))]
    parts = []
    for n in order:
        try:
            raw = zf.read(n).decode('utf-8', 'replace')
        except Exception:
            continue
        raw = _re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', raw)
        raw = _re.sub(r'(?i)<br[^>]*>|</p>|</h[1-6]>|</div>|</li>|</tr>', '\n', raw)
        txt = _html.unescape(_re.sub(r'<[^>]+>', ' ', raw))
        txt = _re.sub(r'[ \t]+', ' ', txt)
        txt = _re.sub(r'\n\s*\n\s*\n+', '\n\n', txt)
        if txt.strip():
            parts.append(txt.strip())
    return '\n\n'.join(parts)


def _fb2_extract_text(data):
    """FB2 (xml ebook) -> plain text: drop binaries, strip tags."""
    import re as _re, html as _html
    raw = data.decode('utf-8', 'replace')
    raw = _re.sub(r'(?is)<binary\b.*?</binary>', ' ', raw)
    raw = _re.sub(r'(?is)<description\b.*?</description>', ' ', raw)
    raw = _re.sub(r'(?i)</p>|</v>|</title>|</subtitle>|</stanza>', '\n', raw)
    txt = _html.unescape(_re.sub(r'<[^>]+>', ' ', raw))
    txt = _re.sub(r'[ \t]+', ' ', txt)
    txt = _re.sub(r'\n\s*\n\s*\n+', '\n\n', txt)
    return txt.strip()


@app.post('/book-to-mp3')
def book_to_mp3():
    """Book upload -> {result_url,size_bytes,dur_s,chars,segments,truncated,text_url[,audio_b64]}."""
    import re as _re
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    app.logger.info("book-to-mp3 in sha256=%s size=%d name=%s", _sha256(data), len(data), fname)
    ext = (os.path.splitext(fname)[1] or '').lower()
    workdir = tempfile.mkdtemp(prefix='book_', dir='/tmp')
    try:
        text = ''
        if ext == '.pdf':
            doc = fitz.open(stream=data, filetype='pdf')
            try:
                if doc.needs_pass:
                    return _err('password_protected', 422)
                text = '\n'.join(page.get_text('text') for page in doc)
            finally:
                doc.close()
        elif ext == '.epub':
            text = _epub_extract_text(data)
        elif ext == '.fb2':
            text = _fb2_extract_text(data)
        elif ext == '.docx':
            import docx
            in_path = os.path.join(workdir, 'in.docx')
            with open(in_path, 'wb') as fh:
                fh.write(data)
            text = '\n'.join(p.text for p in docx.Document(in_path).paragraphs)
        elif ext in ('.txt', '.md'):
            text = data.decode('utf-8', errors='replace')
        else:
            return _err('unsupported_type', 415)
        del data
        # de-hyphenate PDF line wraps + light whitespace cleanup
        text = _re.sub(r'-\n(?=[a-zа-яіїєґ])', '', text)
        text = '\n'.join(ln.strip() for ln in text.splitlines())
        text = _re.sub(r'\n{3,}', '\n\n', text).strip()
        if len(text) < 40:
            return _err('no_text', 422)
        truncated = len(text) > _BOOK_CHAR_CAP
        if truncated:
            text = text[:_BOOK_CHAR_CAP]
        segs = _atr_chunk_text(text, _BOOK_SEG_CHARS)
        if not segs:
            return _err('no_text', 422)
        est_dur = int(len(text) / 14.0)            # ~14 chars/s spoken Ukrainian
        _prog_file = (request.form.get('progress_file') or '').strip()
        _prog_path = os.path.join('/audio_results', _prog_file) if _prog_file else None

        def _prog(sd, stot):
            if not _prog_path:
                return
            try:
                with open(_prog_path, 'w') as _pf:
                    _pf.write('%d %d %d' % (sd, stot, est_dur))
            except Exception:
                pass

        seg_dir = os.path.join(workdir, 'seg')
        os.makedirs(seg_dir, exist_ok=True)
        mp3s = []
        _prog(0, len(segs))
        for i, sg in enumerate(segs):
            out = os.path.join(seg_dir, 'b_%05d.mp3' % i)
            try:
                _book_synth_seg(sg, out, workdir)
                mp3s.append(out)
            except Exception as e:
                app.logger.error('book tts seg %d/%d err: %s', i + 1, len(segs), str(e)[:160])
            _prog(i + 1, len(segs))
        if not mp3s:
            return _err('tts_failed', 500)
        final_mp3 = os.path.join(workdir, 'book.mp3')
        _atr_concat_mp3(mp3s, final_mp3, workdir)
        shutil.rmtree(seg_dir, ignore_errors=True)
        base = os.path.splitext(os.path.basename(fname))[0] or 'book'
        url, _rn, dest = _atr_save_result_file(final_mp3, base, 'mp3')
        src = dest or final_mp3
        size = os.path.getsize(src)
        dur_s = int(_atr_ffprobe_dur(src))
        text_url = _atr_save_text_result(text, base, 'book')
        app.logger.info('book-to-mp3 done: chars=%d segs=%d size=%d dur=%ds trunc=%s',
                        len(text), len(segs), size, dur_s, truncated)
        out_json = {'ok': True, 'result_url': url, 'size_bytes': size, 'dur_s': dur_s,
                    'chars': len(text), 'segments': len(segs), 'truncated': truncated,
                    'text_url': text_url}
        if size <= 45 * 1024 * 1024:
            import base64 as _b64
            with open(src, 'rb') as fh:
                out_json['audio_b64'] = _b64.b64encode(fh.read()).decode('ascii')
            out_json['audio_fmt'] = 'mp3'
        return jsonify(out_json)
    except Exception as e:                                   # noqa: BLE001
        app.logger.error('book-to-mp3 failed: %s', repr(e)[:300])
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.post('/audio-translate-ua')
def audio_translate_ua():
    """English audio upload -> Ukrainian-voice MP3 (Whisper -> translate-9b -> Piper)."""
    import base64 as _b64
    try:
        data, fname = _recv_file()
    except ValueError as e:
        return _err(str(e))
    language = request.form.get('language', 'en')      # source language (default EN)
    app.logger.info("audio-translate-ua in sha256=%s size=%d name=%s",
                    _sha256(data), len(data), fname)
    workdir = tempfile.mkdtemp(prefix='atr_', dir='/tmp')
    try:
        # 0) Persist the upload to disk immediately and drop the RAM copy. Even a
        #    200 MB lecture then costs one on-disk file, not a resident bytes obj.
        in_path = os.path.join(workdir, 'input.src')
        with open(in_path, 'wb') as fh:
            fh.write(data)
        del data                                   # free the upload RAM copy NOW

        dur_s = int(_atr_ffprobe_dur(in_path))
        # live progress for the bot's Telegram status (segment X/N + minutes)
        _prog_file = (request.form.get('progress_file') or '').strip()
        _prog_path = os.path.join('/audio_results', _prog_file) if _prog_file else None
        def _atr_prog(sd, stot):
            if not _prog_path:
                return
            try:
                with open(_prog_path, 'w') as _pf:
                    _pf.write('%d %d %d' % (sd, stot, dur_s))
            except Exception:
                pass

        # 1) Segment the whole input on disk (7-min 16 kHz mono WAV chunks).
        try:
            seg_paths = _atr_segment_input(in_path, workdir)
        except Exception as e:
            app.logger.error('atr segment err: %s', str(e)[:200])
            return _err('segment_failed', 500)
        try:
            os.unlink(in_path)                     # source no longer needed
        except Exception:
            pass
        if not seg_paths:
            return _err('no_audio', 422)

        # 2) Process ONE segment at a time: Whisper -> translate -> Piper -> mp3.
        #    Per-segment MP3s accumulate on disk (tiny, ~3 MB / 7 min); the WAVs
        #    are deleted as we go so tmpfs/RAM never grow with lecture length.
        ua_mp3_dir = os.path.join(workdir, 'uaseg')
        os.makedirs(ua_mp3_dir, exist_ok=True)
        en_parts, ua_parts, ua_mp3_paths = [], [], []
        whisper_ok = False
        _atr_prog(0, len(seg_paths))
        for idx, seg in enumerate(seg_paths):
            seg_en = ''
            try:
                with open(seg, 'rb') as fh:
                    seg_bytes = fh.read()
                # RETRY on whisper crash: whisper (:8771) OOM-dies on long lectures; the
                # host watchdog restarts it within ~2 min, so wait+retry the segment
                # instead of dropping it -> the full lecture completes (was: 6/8 segs).
                import time as _tmod
                _wtries = int(os.getenv('ATR_WHISPER_RETRIES', '8'))
                for _wt in range(_wtries):
                    try:
                        seg_en, _info = _atr_whisper_en(seg_bytes, 'seg_%04d.wav' % idx, language, 'transcribe')
                        break
                    except Exception as _we:
                        if _wt == _wtries - 1:
                            raise
                        app.logger.error('atr whisper seg %d try %d/%d err (%s) -> wait 20s for whisper restart',
                                         idx, _wt + 1, _wtries, str(_we)[:120])
                        _tmod.sleep(20)
                del seg_bytes
            except Exception as e:
                app.logger.error('atr whisper seg %d FAILED after retries: %s', idx, str(e)[:160])
                if idx == 0 and not whisper_ok:
                    return _err('whisper_unavailable', 502)
                seg_en = ''
            finally:
                try:
                    os.unlink(seg)                 # free the input WAV segment
                except Exception:
                    pass
            if not (seg_en or '').strip():
                continue
            whisper_ok = True
            en_parts.append(seg_en.strip())
            try:
                seg_ua = _atr_translate_uk(seg_en)
            except Exception as e:
                app.logger.error('atr translate seg %d err: %s', idx, str(e)[:160])
                seg_ua = ''
            if not (seg_ua or '').strip():
                continue
            ua_parts.append(seg_ua.strip())
            try:
                out_mp3 = os.path.join(ua_mp3_dir, 'ua_%04d.mp3' % idx)
                _atr_synth_seg_mp3(seg_ua, out_mp3, workdir)
                ua_mp3_paths.append(out_mp3)
            except Exception as e:
                app.logger.error('atr tts seg %d err: %s', idx, str(e)[:160])
            app.logger.info('atr seg %d/%d done en=%d ua=%d mp3s=%d',
                            idx + 1, len(seg_paths), len(seg_en), len(seg_ua), len(ua_mp3_paths))
            _atr_prog(idx + 1, len(seg_paths))

        en_text = '\n'.join(en_parts).strip()
        ua_text = '\n'.join(ua_parts).strip()
        if not en_text:
            return _err('no_speech', 422)
        if not ua_mp3_paths:
            return _err('tts_failed', 500)

        # 3) Concatenate the per-segment UA MP3s on disk -> one final MP3.
        final_mp3 = os.path.join(workdir, 'final_ua.mp3')
        try:
            _atr_concat_mp3(ua_mp3_paths, final_mp3, workdir)
        except Exception as e:
            app.logger.error('atr concat err: %s', str(e)[:200])
            return _err('concat_failed', 500)
        # per-segment mp3s no longer needed
        for p in ua_mp3_paths:
            try:
                os.unlink(p)
            except Exception:
                pass

        size_bytes = os.path.getsize(final_mp3)
        base = os.path.splitext(fname or 'audio')[0] or 'audio'

        # 4) Write the final MP3 straight into the shared results dir (nginx-served).
        result_url, result_name, result_path = _atr_save_result_file(final_mp3, base, 'mp3')

        # 5) Transcripts: cap what we return inline; stash the full text as .txt links.
        ua_text_url = _atr_save_text_result(ua_text, base, 'ua') if len(ua_text) > _ATR_TEXT_TG_MAX else None
        en_text_url = _atr_save_text_result(en_text, base, 'en') if len(en_text) > _ATR_TEXT_TG_MAX else None
        ua_out = ua_text if len(ua_text) <= _ATR_TEXT_TG_MAX else (ua_text[:_ATR_TEXT_TG_MAX] + ' …')
        en_out = en_text if len(en_text) <= _ATR_TEXT_TG_MAX else (en_text[:_ATR_TEXT_TG_MAX] + ' …')

        app.logger.info("audio-translate-ua out mp3 size=%d segs=%d en_len=%d ua_len=%d url=%s",
                        size_bytes, len(ua_mp3_paths), len(en_text), len(ua_text), result_url or '-')

        resp = {'ok': True,
                'en_text': en_out,
                'ua_text': ua_out,
                'en_text_url': en_text_url,
                'ua_text_url': ua_text_url,
                'result_url': result_url,
                'result_path': result_path,
                'result_name': result_name,
                'size_bytes': size_bytes,
                'audio_fmt': 'mp3',
                'dur_s': dur_s,
                'segments': len(seg_paths),
                'voice': os.path.basename(_PIPER_VOICE)}
        # Small-file fallback: keep inline base64 only for modest outputs so the
        # existing Telegram-document path still works when there is no link.
        if size_bytes <= _ATR_B64_MAX:
            with open(final_mp3, 'rb') as fh:
                resp['audio_b64'] = _b64.b64encode(fh.read()).decode('ascii')
        return jsonify(resp)
    except Exception as e:
        app.logger.error('audio-translate-ua failed: %s', str(e)[:200])
        return _err('process_failed', 500)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ──────────────────────────────────────────────────────────────────────────
#  /gen-docx — render a Ukrainian office document (СЕД/ДСТУ 4163) to .docx
#  Body: {text: "<document body, lines / light markdown>", title?, filename?}
#  Returns: {ok, url, filename}. Uses python-docx; Times New Roman 14, A4 margins.
#  Light markdown understood: '# '/'## ' headings, '**bold**', '- '/'• ' bullets,
#  'НАКАЗУЮ:'/'ЗОБОВ'ЯЗУЮ:' emphasised, a line that is only '___' as a right-aligned
#  signature separator. Everything else = justified body paragraph.
# ──────────────────────────────────────────────────────────────────────────
@app.post('/gen-docx')
def gen_docx():
    import re as _re
    import uuid as _uuid
    data = request.get_json(force=True, silent=True) or {}
    text = str(data.get('text') or data.get('body') or '').strip()
    title = str(data.get('title') or '').strip()
    base = str(data.get('filename') or title or 'dokument').strip()
    if not text:
        return jsonify({'ok': False, 'error': 'text required'}), 400
    try:
        import docx
        from docx.shared import Pt, Cm, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.oxml.ns import qn
    except Exception as e:
        return jsonify({'ok': False, 'error': 'python-docx missing: ' + str(e)[:120]}), 500
    try:
        doc = docx.Document()
        # base style: Times New Roman 14, A4, ДСТУ-ish margins
        st = doc.styles['Normal']
        st.font.name = 'Times New Roman'
        st.font.size = Pt(14)
        try:
            st.element.rPr.rFonts.set(qn('w:cs'), 'Times New Roman')
        except Exception:
            pass
        for section in doc.sections:
            section.page_height = Cm(29.7); section.page_width = Cm(21.0)     # A4
            section.left_margin = Cm(3.0); section.right_margin = Cm(1.5)     # ДСТУ поля
            section.top_margin = Cm(2.0); section.bottom_margin = Cm(2.0)

        def _runs(par, s):
            # split **bold** spans
            for i, chunk in enumerate(_re.split(r'\*\*(.+?)\*\*', s)):
                if chunk == '':
                    continue
                r = par.add_run(chunk)
                if i % 2 == 1:
                    r.bold = True

        _bullet_re = _re.compile(r'^\s*[-•]\s+')
        for raw in text.replace('\r\n', '\n').split('\n'):
            line = raw.rstrip()
            if not line.strip():
                doc.add_paragraph()
                continue
            if line.startswith('## '):
                p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r = p.add_run(line[3:].strip()); r.bold = True
            elif line.startswith('# '):
                p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                r = p.add_run(line[2:].strip()); r.bold = True; r.font.size = Pt(15)
            elif line.strip() in ('___', '____', '_____'):
                p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
                p.add_run('_______________')
            elif _bullet_re.match(line):
                p = doc.add_paragraph(style='List Bullet'); _runs(p, _bullet_re.sub('', line))
            elif _re.match(r'^(НАКАЗУЮ|ЗОБОВ.ЯЗУЮ|ВИРІШИВ|УХВАЛИВ|ПОСТАНОВЛЯЮ)\s*:?\s*$', line.strip()):
                p = doc.add_paragraph(); r = p.add_run(line.strip()); r.bold = True
            else:
                p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                _runs(p, line)

        if not os.path.isdir(_ATR_RESULTS_DIR):
            return jsonify({'ok': False, 'error': 'results dir missing'}), 500
        safe = _translit_fname(base, fallback='dokument')
        fname = '%s_%s.docx' % (_uuid.uuid4().hex, safe)
        dest = os.path.join(_ATR_RESULTS_DIR, fname)
        doc.save(dest)
        url = _ATR_UPLOAD_BASE + '/audio/' + fname
        return jsonify({'ok': True, 'url': url, 'filename': safe + '.docx',
                        'size': os.path.getsize(dest)})
    except Exception as e:
        app.logger.warning('gen-docx failed: %s', repr(e)[:200])
        return jsonify({'ok': False, 'error': str(e)[:200]}), 500


if __name__ == '__main__':
    # Dev only; production uses gunicorn (see Dockerfile CMD).
    app.run(host='0.0.0.0', port=8799)
