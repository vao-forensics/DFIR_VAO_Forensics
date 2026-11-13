# =============================================================================
#  case_maintainer_addtools.py — "Додаткові інструменти" (Additional Tools)
# -----------------------------------------------------------------------------
#  NEW module for the Alpine bot container (case-maintainer). It implements the
#  "🧰 Додаткові інструменти" submenu and its per-tool state machine.
#
#  Design constraints it follows (matching the existing app.py):
#    * Telegram transport = RAW Bot API over urllib (NO python-telegram-bot).
#      Messages are sent WITHOUT parse_mode (evidence paths/<>/| break HTML).
#    * Inline keyboards with callback_data "tool:<name>" — the n8n CB Router
#      maps these to the Flask endpoints defined at the bottom of this file.
#    * LLM access via build_chat_payload() -> urllib POST to LLM_URL.
#    * Pure-python tools (hash/base64/hex/defang/IOC/EML) run INLINE in this
#      Alpine container. Native tools (PDF unlock/watermark, OCR, meta, doc text
#      extraction for translation) PROXY to the tools-sidecar over httpx.
#    * Forensic hygiene: per-request /tmp/<uuid>/ workdir, deleted on completion;
#      log only file hashes, never contents or passwords.
#
#  WIRING (do this in app.py, see DEPLOY.md):
#      from case_maintainer_addtools import register_addtools
#      register_addtools(app, _tg_send_plain=_tg_send_plain,
#                        TG_BOT_TOKEN=TG_BOT_TOKEN,
#                        build_chat_payload=build_chat_payload,
#                        LLM_URL=LLM_URL, LLM_MODEL=LLM_MODEL)
#
#  The module is dependency-injected with the bot's existing helpers so it never
#  re-imports the 561 KB app.py (avoids a circular import) and reuses the exact
#  same Telegram/LLM plumbing.
# =============================================================================
from __future__ import annotations

import base64
import binascii
import gzip
import html
import hashlib
import json
import math
import threading
import os
import re
from html.parser import HTMLParser
import shutil
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib

import httpx  # already installed in the Alpine image (httpx 0.28.1)

# ── Injected at register time (set by register_addtools) ──────────────────────
_CTX: dict = {}          # holds tg_send_plain, TG_BOT_TOKEN, build_chat_payload, ...
log = None               # app.logger, injected

# ── Sidecar base URL (internal docker DNS name; overridable via env) ──────────
SIDECAR_URL = os.getenv('DFIR_TOOLS_SIDECAR_URL', 'http://tools-sidecar:8799').rstrip('/')
WHISPER_URL = os.getenv('DFIR_WHISPER_URL', 'http://192.168.134.1:8771').rstrip('/')  # host GPU Whisper large-v3
IMG_ENHANCE_URL = os.getenv('DFIR_IMG_ENHANCE_URL', 'http://192.168.134.1:8772').rstrip('/')  # host Real-ESRGAN x4
DIARIZE_URL = os.getenv('DFIR_DIARIZE_URL', 'http://192.168.134.1:8773').rstrip('/')  # host diarized transcription

# ── Audio-translate result delivery via download link (2026-07-05) ────────────
#  Telegram sendDocument caps bot uploads at 50 MB, but translated lecture MP3s
#  can be much bigger. Results are therefore ALSO written to a shared dir
#  (host /srv/dfir/var/audio_results -> bot /audio_results, served by the
#  dfir-uploader nginx at http://<VPN>:8080/audio/<name>). Files > the
#  threshold are delivered by LINK ONLY; smaller ones keep the Telegram document
#  plus the link as fallback. Old results are pruned on write (>7 days).
AUDIO_RESULTS_DIR = os.getenv('DFIR_AUDIO_RESULTS_DIR', '/audio_results')
AUDIO_TG_LIMIT = int(os.getenv('DFIR_AUDIO_TG_LIMIT', str(45 * 1024 * 1024)))  # ~45 MB, safety margin under TG 50 MB
AUDIO_RESULTS_KEEP_DAYS = int(os.getenv('DFIR_AUDIO_RESULTS_KEEP_DAYS', '7'))



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


def _audio_results_save(data: bytes, orig_base: str, ext: str = 'mp3'):
    """Write a result audio file to the shared results dir under a hard-to-guess
    uuid-prefixed name; prune files older than AUDIO_RESULTS_KEEP_DAYS.
    Returns (public_url, filename) or (None, None) if the dir is unavailable.
    Best-effort: NEVER raises (link delivery is additive to the existing flow)."""
    try:
        if not os.path.isdir(AUDIO_RESULTS_DIR):
            if log:
                log.warning('[addtools] audio results dir missing: %s', AUDIO_RESULTS_DIR)
            return None, None
        # retention: prune old results (best-effort, ignores errors)
        now = time.time()
        try:
            for f in os.listdir(AUDIO_RESULTS_DIR):
                p = os.path.join(AUDIO_RESULTS_DIR, f)
                if os.path.isfile(p) and now - os.path.getmtime(p) > AUDIO_RESULTS_KEEP_DAYS * 86400:
                    os.unlink(p)
        except Exception:
            pass
        safe = _translit_fname(orig_base, fallback='audio')
        fname = '%s_%s_ua.%s' % (uuid.uuid4().hex, safe, ext)
        tmp = os.path.join(AUDIO_RESULTS_DIR, '.' + fname + '.part')
        with open(tmp, 'wb') as fh:
            fh.write(data)
        os.replace(tmp, os.path.join(AUDIO_RESULTS_DIR, fname))
        base_url = os.environ.get('DFIR_UPLOAD_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080').rstrip('/')
        url = base_url + '/audio/' + fname
        if log:
            log.info('[addtools] audio result saved: %s (%d bytes) -> %s', fname, len(data), url)
        return url, fname
    except Exception as e:                                   # noqa: BLE001
        if log:
            log.warning('[addtools] audio result save failed: %s', repr(e)[:200])
        return None, None
# Operational trigger-word stems (Ukrainian inflections matched). Override via env
# DFIR_TRIGGER_WORDS (comma-separated). Stems so "наркотик" hits наркотики/наркотиків.
# TRIGGER_EXPANDED_V2 — operative trigger stems, grouped. Matching is anchored
# to a WORD START (see _highlight_triggers) so short stems no longer light up
# substrings (e.g. 'нал' inside 'канал'). Override fully via DFIR_TRIGGER_WORDS.
_TRIGGER_STEMS = [t.strip().lower() for t in os.getenv('DFIR_TRIGGER_WORDS',
    # наркотики
    'наркотик,товар,вага,кіло,грам,доза,закладк,кладмен,кокаїн,кокс,героїн,амфетамін,фен,метадон,гашиш,марихуан,травк,конопл,сіль,меф,мефедрон,спайс,парті,оптом,розниц,фасуван,фасов,пакуван,шишк,план,ширк,опій,екстаз,колес,марк,'
    # зброя
    'зброя,ствол,пістолет,макаров,автомат,калаш,патрон,набої,боєприпас,граната,вибухівк,тротил,обріз,карабін,гвинтівк,глушник,травмат,кастет,boom,'
    # гроші
    'гроші,готівк,кеш,безнал,переказ,хабар,відкат,борг,залог,долар,євро,гривен,валют,обмінник,відмиван,транш,конверт,комісі,лям,косар,штук,розрахунок,оплат,предоплат,завдаток,'
    # зустрічі / логістика
    'зустріч,стрілк,адрес,квартир,гараж,схов,тайник,координат,локаці,точк,район,підвал,дача,склад,контейнер,вокзал,забер,привез,передач,залиш,закинь,скинь,'
    # погрози / насильство
    'дах,кришуван,вбивств,замовленн,замочити,прибрати,усунути,погроз,викуп,заручник,розборк,наїзд,спалил,розвести,розрулити,'
    # протидія поліції
    'мент,поліці,обшук,прослушк,прослух,хвіст,стеж,злив,стукач,інформатор,засад,затриман,спецназ,сізо,зона,статт,строк,посадк,операці,легав,'
    # ролі
    'барига,посередник,курєр,смотрящ,авторитет,братв,банд,угрупован,замовник,наводчик,дилер,збувач,'
    # документи / транспорт / комунікації
    'паспорт,карт,рахунок,iban,крипт,біткоїн,гаманець,номер,держномер,vin,тачк,бус,маршрут,кордон,контрабанд,фальшив,підробк,телег,сигнал,вайбер,симк,трубк,набери,созвон,відпиш').split(',') if t.strip()]


def _highlight_triggers(text):
    """Wrap operative trigger stems (and their UA inflections) with 🔴…🔴 and
    collect which fired. Case-insensitive, Cyrillic/Latin word continuations."""
    import re as _re
    found = set()
    out = text
    for stem in _TRIGGER_STEMS:
        try:
            pat = _re.compile('(?i)(?<![a-zA-Zа-яА-ЯіїєґІЇЄҐ])(' + _re.escape(stem) + "[a-zA-Zа-яА-ЯіїєґІЇЄҐ0-9'-]*)")
        except Exception:
            continue
        def _r(m):
            found.add(stem)
            return '🔴' + m.group(1) + '🔴'
        out = pat.sub(_r, out)
    return out, found

SIDECAR_TIMEOUT = int(os.getenv('DFIR_TOOLS_SIDECAR_TIMEOUT', '600'))
# Long lectures (whisper + translate + Piper over many 7-min segments) can run
# well past 10 min. The audio-translate job runs on a background thread, so a
# long client ceiling is safe (it never blocks the HTTP request that started it).
AUDIO_SIDECAR_TIMEOUT = int(os.getenv('DFIR_AUDIO_SIDECAR_TIMEOUT', '21600'))

# ── Per-(chat_id,user_id) pending-state registry ──────────────────────────────
#  Mirrors the design's PENDING map. Value: {"tool": str, "stage": str, **data}.
#  In-process dict is fine: one gunicorn worker keeps the bot's global state.
PENDING: dict = {}
PENDING_TTL = int(os.getenv('DFIR_TOOLS_PENDING_TTL', '900'))  # 15 min

# ── Limits / safety ───────────────────────────────────────────────────────────
TG_DOWNLOAD_CAP = 20 * 1024 * 1024     # Telegram bot getFile cap
DECODE_OUTPUT_CAP = 200 * 1024          # cap decoded text shown in chat
HEXVIEW_CAP = 64 * 1024                 # hexdump first N bytes of a binary


# =============================================================================
#  Submenu definition
# =============================================================================
#  callback_data is "tool:<name>". The n8n CB Router routes every "tool:*" and
#  the menu open ("addtools_menu") to /addtools/cb (see n8n_callback_notes.md).
TOOLS_MENU_TITLE = "🧰 Додаткові інструменти"

#  (label, tool_name). Order = display order.
TOOLS_MENU = [
    ("❓ Довідка / Як користуватись",      "help"),           # shows help md
    ("📄 Перекласти PDF (як оригінал)",   "pdf_translate"),  # sidecar pdf2zh (keeps layout)
    ("📄 Зняти пароль з PDF",            "pdf_unlock"),     # sidecar
    ("💧 Прибрати водяний знак",         "pdf_watermark"),  # sidecar
    ("🌐 Перекласти документ → текст",     "translate"),      # sidecar extract + LLM
    ("🔎 OCR — текст зі скану/фото",       "ocr"),            # sidecar OCR
    ("📚 Book-індекс Study (offline)",    "bookidx_index"),     # sidecar (bookidx)
    ("🔬 Аналіз файлу (метадані + вірус)", "fileanalysis"),
    ("🎯 Витягти IOC з тексту",          "iocextract"),     # inline
    ("📧 Email (EML/MSG) → текст",       "email"),          # inline (extract-msg)
    ("🔊 Очистити звук + транскрипт",     "audio_clean"),    # denoise+AGC -> clean audio + text
    ("🌐→🇺🇦 Аудіо: переклад голосом",     "audio_translate_ua"),  # EN audio -> UK spoken MP3
    ("📖→🔊 Книга в MP3 (EPUB/PDF)",       "book_mp3"),        # ebook/doc -> UA-voice audiobook
    ("🖼 Покращення фото (×4 SR)",        "img_enhance"),    # host Real-ESRGAN
    ("🚗 Номер/розмите фото (деблюр)",    "img_plate"),      # host plate deblur sheet
    ("🎙 Розмова: хто-коли (діаризація)", "diarize"),       # host whisper+ecapa
    ("🙂 Відновити обличчя (CodeFormer)", "restore_faces"),  # host CodeFormer
]

# 2026-10-08 (owner): the bot is for DFIR. Translation, audio and image tools load models onto
# cards 1,4 (DFIR lane B) and 2 (lane A), so for ordinary users they are hidden and refused;
# only the admin keeps them. Light CPU tools stay open for everyone.
_ADMIN_ONLY_TOOLS = {
    'pdf_translate', 'translate', 'bookidx_index',
    'audio_clean', 'audio_translate_ua', 'book_mp3', 'diarize',
    'img_enhance', 'img_plate', 'restore_faces',
}


def _tool_from_cb(cb_data: str) -> str:
    parts = str(cb_data or '').split(':')
    if len(parts) >= 3 and parts[0] == 'tool' and parts[1] == 'act':
        return parts[2]
    return parts[1] if len(parts) >= 2 and parts[0] == 'tool' else ''


# --- LLM GPU master toggle (admin) -> host control service :8790 -------------
_LLM_CTRL_URL = os.getenv("DFIR_LLM_CTRL_URL", "http://192.168.100.1:8790")
_LLM_CTRL_TOKEN = os.getenv("DFIR_LLM_CTRL_TOKEN", "")
_LLM_ADMIN_IDS = set(x.strip() for x in os.getenv("DFIR_ADMIN_IDS", "CHANGE_ME_OWNER_CHAT_ID").split(",") if x.strip())


def _llm_ctrl(action):
    """Call the host LLM-control service. action in on/off/status. Returns dict."""
    import urllib.request as _u, json as _j
    method = "GET" if action == "status" else "POST"
    url = _LLM_CTRL_URL + ("/status" if action == "status" else "/" + action)
    req = _u.Request(url, method=method, headers={"X-LLM-Token": _LLM_CTRL_TOKEN})
    with _u.urlopen(req, timeout=30) as r:
        return _j.load(r)


def _fmt_llm_status(d):
    lines = []
    mode = d.get("mode", "?")
    lines.append("🖥 Стан LLM-стека")
    lines.append("Режим: %s" % ("🔴 БРУТФОРС (LLM вимкнено)" if d.get("disabled") else "🟢 LLM активний"))
    lines.append("LLM :1234: %s | Whisper :8771: %s" % ("✅" if d.get("llm") else "❌", "✅" if d.get("whisper") else "❌"))
    ml = d.get("models_loaded") or []
    if ml:
        lines.append("Завантажені моделі: " + ", ".join(ml))
    for c in d.get("cards", []):
        bar = int(c.get("used_mb", 0) / max(c.get("total_mb", 1), 1) * 10)
        lines.append("  card%d: %d/%d MB %s util %d%%" % (
            c.get("i"), c.get("used_mb", 0), c.get("total_mb", 0),
            "▮" * bar + "▯" * (10 - bar), c.get("util", 0)))
    return chr(10).join(lines)


def _do_llm_toggle(chat_id, action):
    """admin-only: on/off/status of the whole LLM+Whisper stack (free GPUs for brute-force)."""
    if str(chat_id) not in _LLM_ADMIN_IDS:
        _send_plain(chat_id, "⛔ Лише для адміністратора.")
        return
    if not _LLM_CTRL_TOKEN:
        _send_plain(chat_id, "⚠️ DFIR_LLM_CTRL_TOKEN не налаштований у боті.")
        return
    try:
        if action in ("on", "off"):
            _send_plain(chat_id, "⏳ %s LLM-стек…" % ("Вмикаю" if action == "on" else "Вимикаю"))
            r = _llm_ctrl(action)
            _send_plain(chat_id, ("🟢 " if action == "on" else "🔴 ") + (r.get("note") or "ok"))
        import time as _t
        _t.sleep(2)
        _send_plain(chat_id, _fmt_llm_status(_llm_ctrl("status")) + chr(10) + _agent_mode_line(),
                    reply_markup=_back_kb(_AGENT_MODE_ROWS))
    except Exception as e:
        _send_plain(chat_id, "❌ Помилка керування LLM: " + str(e)[:160], reply_markup=_back_kb(_AGENT_MODE_ROWS))


# --- Agent 120b mode (2026-10-13, owner): one button frees all 5 cards for 120b in Agent ------
# The bot keeps running; its own LLM calls wait in core/llm_queue.py while the mode file exists.
_LLM_SWAP_URL = os.getenv("DFIR_LLM_URL", "http://192.168.100.1:1234").rstrip("/")
if _LLM_SWAP_URL.endswith("/v1"):
    _LLM_SWAP_URL = _LLM_SWAP_URL[:-3]
_AGENT_MODE_ROWS = [
    [{"text": "🚀 Agent: 120b на всі карти", "callback_data": "tool:llm_big_on"}],
    [{"text": "↩️ Звичайний режим (бот)", "callback_data": "tool:llm_big_off"}],
]


def _agent_mode_line():
    from core.llm_queue import agent_mode_on
    return ("Режим: 🚀 AGENT 120b — бот чекає, карти віддані 120b" if agent_mode_on()
            else "Режим: 🤖 звичайний — карти в бота")


def _swap_running():
    import urllib.request as _u, json as _j
    with _u.urlopen(_LLM_SWAP_URL + "/running", timeout=5) as r:
        return [str(m.get("model")) for m in (_j.load(r).get("running") or [])]


def _do_agent_mode(chat_id, on):
    """admin-only: switch the rig between the bot's models and GPT-OSS-120B for Agent."""
    if str(chat_id) not in _LLM_ADMIN_IDS:
        _send_plain(chat_id, "⛔ Лише для адміністратора.")
        return
    from core.llm_queue import AGENT_MODE_FILE, queue_stats
    import urllib.request as _u, json as _j, time as _t
    if not on:
        try:
            os.remove(AGENT_MODE_FILE)
        except FileNotFoundError:
            pass
        try:
            if "big-120b" in _swap_running():
                _u.urlopen(_LLM_SWAP_URL + "/unload", timeout=60).read()
        except Exception:
            pass
        _send_plain(chat_id, "↩️ Звичайний режим: 120b вивантажено, бот знову працює зі своїми моделями "
                             "(перший запит підвантажить їх, ~30-60 с).", reply_markup=_back_kb(_AGENT_MODE_ROWS))
        return
    from core.llm_queue import agent_mode_set
    agent_mode_set()
    _send_plain(chat_id, "⏳ Режим Agent 120b: бот ставить свої запити на паузу, завантажую 120b на 5 карт (~2 хв)…")

    def _work():
        try:
            t0 = _t.time()
            while queue_stats().get("inflight", 0) and _t.time() - t0 < 900:
                _t.sleep(5)   # let the bot's in-flight call finish before llama-swap evicts its model
            body = _j.dumps({"model": "big-120b", "messages": [{"role": "user", "content": "ok"}],
                             "max_tokens": 1}).encode("utf-8")
            _u.urlopen(_u.Request(_LLM_SWAP_URL + "/v1/chat/completions", data=body,
                                  headers={"Content-Type": "application/json"}), timeout=900).read()
            _send_plain(chat_id, (
                "🚀 120b готова за %d с.%s"
                "У Agent: модель  big-120b , Base URL  http://CHANGE_ME_DFIR_LINK_IP:1234/v1 , контекст 131072, "
                "макс. відповідь ≥ 8000.%s"
                "⏱ Після 15 хв без запитів 120b вивантажується сама (наступний запит Agent "
                "підвантажить її знову, ~2 хв). Бот у цьому режимі чекає — аналізи клієнтів стоять у черзі.%s"
                "Щоб повернути карти боту — «↩️ Звичайний режим».")
                % (_t.time() - t0, chr(10), chr(10), chr(10)), reply_markup=_back_kb(_AGENT_MODE_ROWS))
        except Exception as e:
            _send_plain(chat_id, "❌ 120b не завантажилась: " + str(e)[:160], reply_markup=_back_kb(_AGENT_MODE_ROWS))
    threading.Thread(target=_work, daemon=True).start()


LLM_AGENT_HELP_TEXT = """🤖 Підключення LLM-агента (OpenClaw)

🌐 VPN-лінк (WireGuard — з будь-якого пристрою у VPN):
   Base URL:  http://CHANGE_ME_DFIR_LINK_IP:1234/v1
   (та сама адреса, що й бот: ВМ проксіює LLM з рігу)
   API key:   local  (підійде будь-який рядок)
   Тип API:   OpenAI-compatible (Chat Completions)

⭐ МОДЕЛЬ ДЛЯ АГЕНТА (нецензурована, контекст 131072 = 128K):
   agent-30b
   (аліаси: agent, agent-cli, uncensored)

   Альтернатива: gpt-small-20b — теж нецензурована, 65536,
   але це робоча модель бота (карта 0) — агент на ній
   конкуруватиме з ботом за GPU.

⚙ Agent:
   1) Settings → Provider → OpenAI-compatible (Chat Completions)
   2) Base URL: http://CHANGE_ME_DFIR_LINK_IP:1234/v1   API key: local
   3) Model id: agent-30b
   4) Context length: 131072  (НЕ 32768!)
   5) Max reply tokens: 8000 (мінімум 4000)

⚙ OpenClaw:
   1) Провайдер: OpenAI-compatible / custom endpoint
   2) base_url: http://CHANGE_ME_DFIR_LINK_IP:1234/v1   api_key: local
   3) model: agent-30b   context: 131072

💡 Поради:
   • У system prompt агента додай: «Відповідай українською» —
     без system prompt abliterated-моделі перескакують на іншу мову.
   • Перший запит повільний (~20–40с) — модель завантажується в GPU.
   • Якщо LLM вимкнено кнопкою «🔴 LLM вимк (брутфорс)» —
     агент не відповідатиме, спершу увімкни LLM."""


def _send_llm_agent_help(chat_id):
    """admin-only: how to wire an external LLM agent (OpenClaw) to the host llama-swap."""
    if str(chat_id) not in _LLM_ADMIN_IDS:
        _send_plain(chat_id, "⛔ Лише для адміністратора.")
        return
    _send_plain(chat_id, LLM_AGENT_HELP_TEXT, reply_markup=_back_kb())


#  Ukrainian prompt shown when a tool is selected (first stage).
TOOL_PROMPT_UA = {
    "pdf_translate": ("📄 Надішліть PDF (можна захищений паролем) — поверну ZIP: index.html де ЛІВОРУЧ оригінал сторінки, ПРАВОРУЧ переклад українською. Переклад локальний (translate-9b), нічого в хмару. "
                      "збереженням розмітки. Це РОБОЧА копія, оригінал-доказ "
                      "не змінюється."),
    "pdf_unlock":   "📄 Надішліть PDF-файл, з якого потрібно зняти пароль.",
    "book_mp3":     ("📖 Надішліть книгу файлом — EPUB, PDF, FB2, DOCX або TXT (до 20 МБ). Витягну текст і озвучу українським голосом (Piper TTS, все локально) — повернеться MP3-аудіокнига + витягнутий текст. Велика книга = довга обробка (прогрес показуватиму) і доставка посиланням. Читаю текст «як є», без перекладу — для англомовних книг спершу скористайтесь перекладом документа."),
    "bookidx_index":   "📚 Надішліть PDF курсу Study — згенерую офлайн-індекс для іспиту (тема→сторінка) + cheat-sheet команд. Контент нікуди не йде, лише локальна ШІ. Якщо PDF запаролений — попрошу пароль.",
    "pdf_watermark": ("💧 Надішліть PDF-файл для видалення водяного знака.\n"
                      "⚠️ Це робота з РОБОЧОЮ копією — не з оригіналом доказу "
                      "(редагування змінює хеш файлу)."),
    "translate":    "🌐 Надішліть документ (PDF / DOCX / TXT) для перекладу українською.",
    "ocr":          "🔎 Надішліть скан (PDF або фото) — зроблю текстовий шар (OCR).",
    "meta":         "🧬 Надішліть файл (PDF / DOCX / фото) для читання метаданих.",
    "fileanalysis": "🔬 Надішліть будь-який файл — прочитаю метадані, перевірю на вірус (YARA) і зроблю статичний аналіз (strings / PE / ентропія). Файл НЕ запускається і стирається після обробки.",
    "yara":         "🧬 Надішліть підозрілий файл (exe/dll/скрипт/будь-який) — просканую YARA-правилами на малварь: RAT/тунелі, credential-dump, webshell, ransomware, RDP-wrapper.",
    "hash":         "#️⃣ Надішліть будь-який файл — обчислю MD5 / SHA1 / SHA256.",
    "defang":       "🛡 Надішліть текст з IOC. Я перемкну defang ⇄ refang.",
    "decode":       "🔁 Надішліть рядок для декодування (base64 / hex / URL / gzip / ROT13).",
    "iocextract":   "🎯 Надішліть текст — витягну IP / домени / URL / email / хеші / CVE.",
    "email":        "📧 Надішліть файл .eml або .msg — розберу заголовки і вкладення.",
    "hexview":      "#️⃣ Надішліть невеликий файл — покажу hexdump і printable strings.",
    "restore_faces": ("🙂 Надішліть фото з нечітким обличчям — відновлю/підвищу різкість обличчя (CodeFormer). \n⚠️ AI-відновлення: для ЗАЧІПКИ, не як доказ. Оригінал не змінюється, банер + лог SHA-256."),
    "diarize":     ("🎙 Надішліть аудіо/відео розмови — зроблю транскрипт із розміткою ХТО говорить (Спікер 1/2…) і КОЛИ (таймкоди). Оперативні слова-тригери (наркотики/зброя/гроші/зустріч…) підсвічуються 🔴. Мова авто (укр/рос/мікс). Будь-який формат."),
    "img_enhance":  ("🖼 Надішліть фото — підвищу роздільність ×4 (Real-ESRGAN) для кращої читабельності облич / номерів / дрібних деталей.\n⚠️ Це AI-апскейл: для ЗАЧІПКИ, не як доказ (модель може домислити деталі). Оригінал не змінюється; результат позначається банером + лог SHA-256."),
    "img_plate":    ("🚗 Надішліть фото розмитого/нечіткого номерного знака (або будь-яке розмите фото) — поверну КОНТАКТНИЙ ЛИСТ варіантів: деблюр руху, деблюр розфокусу, контраст+різкість, сірий контраст і Super-Res ×4. Оберіть найчіткіший для зчитування.\n⚠️ Деконволюція — детермінована (без домислювання символів); SR — окремий AI-варіант. Для ЗАЧІПКИ, не доказ. Оригінал не змінюється, банер + лог SHA-256."),
    "transcribe":   ("🎤 Надішліть аудіо або відео (голосове, mp3, wav, m4a, ogg, opus, flac, aac, mp4, mkv, webm…) — розпізнаю мовлення (Whisper large-v3, GPU).\nМову визначаю автоматично (українська / російська / мікс). Низька якість запису — це нормально, модель витягне максимум."),
    "audio_clean":  ("🔊 Надішліть тихий/шумний аудіо- чи відеозапис — зроблю діагностику (рівень/шум/SNR), приберу шум і фон, підсилю голос і поверну ДВА результати: 1) ОЧИЩЕНУ аудіодоріжку (чути голос), 2) ТЕКСТ-транскрипт. Будь-який формат, мова авто (укр/рос/мікс)."),
    "audio_translate_ua": ("🌐→🇺🇦 Надішліть АНГЛОМОВНИЙ аудіо- чи відеозапис (mp3, wav, m4a, ogg, opus, mp4…) — розпізнаю англійську (Whisper), перекладу українською (локальна ШІ) і озвучу українським голосом (Piper TTS). Поверну: 1) MP3 з українською озвучкою, 2) текст перекладу + оригінальний англійський текст. Все локально, нічого в хмару."),
    "ioc_add":      "Встав текст (звіт/лист/нотатки) — я сама виділю індикатори для цього кейсу",
}

#  Which tools expect a FILE first vs TEXT first.
TOOL_INPUT_KIND = {
    "pdf_translate": "file",
    "bookidx_index": "file",
    "pdf_unlock": "file", "pdf_watermark": "file", "translate": "file",
    "ocr": "file", "meta": "file", "hash": "file", "email": "file", "fileanalysis": "file",
    "yara": "file",
    "hexview": "file",
    "transcribe": "file",
    "audio_clean": "file",
    "audio_translate_ua": "file",
    "book_mp3": "file",
    "img_enhance": "file",
    "img_plate": "file",
    "diarize": "file",
    "restore_faces": "file",
    "defang": "text", "decode": "text", "iocextract": "text",
    "ioc_add": "text",
}

#  Stable error-code -> Ukrainian user message (sidecar returns codes).
SIDECAR_ERR_UA = {
    "no_file":        "❌ Файл не отримано.",
    "empty_file":     "❌ Порожній файл.",
    "too_large":      "❌ Файл завеликий (ліміт ~20 МБ).",
    "bad_password":   "❌ Невірний пароль до PDF.",
    "unsupported_type": "❌ Непідтримуваний тип файлу.",
    "process_failed": "❌ Не вдалося обробити файл.",
    "whisper_unavailable": "❌ Сервіс розпізнавання мовлення недоступний. Спробуйте пізніше.",
    "no_speech":      "ℹ️ Мовлення не розпізнано (тиша / лише шум?). Спробуйте інший або гучніший файл.",
    "translate_unavailable": "❌ Сервіс перекладу недоступний. Спробуйте пізніше.",
    "translate_empty": "❌ Переклад не вдався (порожня відповідь моделі).",
    "tts_failed":     "❌ Синтез української озвучки не вдався.",
    "no_watermark":   ("ℹ️ Водяних знаків-анотацій не знайдено. Якщо знак "
                       "«вбудований» у зображення, надішліть його текст "
                       "(напр. CONFIDENTIAL) — я спробую прибрати растровий знак."),
    "watermark_not_found": ("ℹ️ Вказаний текст водяного знака не знайдено у файлі "
                            "(ні у тексті, ні у зображеннях). Перевірте написання "
                            "або надішліть точний текст знака."),
}



# =============================================================================
#  Telegram helpers (urllib, matching app.py conventions)
# =============================================================================
def _tg_token() -> str:
    return _CTX.get('TG_BOT_TOKEN') or ''


def _send_plain(chat_id, text, reply_markup=None):
    """Delegate to the bot's own _tg_send_plain (handles _tg_clean + no parse_mode)."""
    fn = _CTX.get('tg_send_plain')
    if fn:
        return fn(chat_id, text, reply_markup=reply_markup)
    # Fallback (should not happen) — minimal direct send.
    try:
        body = {'chat_id': str(chat_id), 'text': str(text)}
        if reply_markup:
            body['reply_markup'] = reply_markup
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{_tg_token()}/sendMessage',
            data=json.dumps(body, ensure_ascii=False).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=12)
    except Exception:
        pass


def _tg_get_file_path(file_id: str) -> str:
    """getFile -> result.file_path (the relative path on Telegram's file server)."""
    url = f'https://api.telegram.org/bot{_tg_token()}/getFile'
    body = json.dumps({'file_id': file_id}).encode('utf-8')
    req = urllib.request.Request(url, data=body,
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=20) as r:
        res = json.loads(r.read().decode('utf-8'))
    return res['result']['file_path']


def _tg_download(file_id: str, workdir: str) -> str:
    """Download a Telegram file into workdir, return the local path. Enforces cap."""
    fpath = _tg_get_file_path(file_id)
    url = f'https://api.telegram.org/file/bot{_tg_token()}/{fpath}'
    local = os.path.join(workdir, os.path.basename(fpath) or f'{uuid.uuid4().hex}.bin')
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read(TG_DOWNLOAD_CAP + 1)
    if len(data) > TG_DOWNLOAD_CAP:
        raise ValueError("too_large")
    with open(local, 'wb') as fh:
        fh.write(data)
    if log:
        log.info("[addtools] downloaded sha256=%s size=%d", _sha256_file(local), len(data))
    return local


def _tg_send_document(chat_id, file_bytes: bytes, filename: str, caption: str = "",
                      content_type: str = 'application/octet-stream'):
    """sendDocument via multipart/form-data over urllib — same pattern as app.py."""
    boundary = uuid.uuid4().hex

    def _part(name, value, fn=None, ct='text/plain'):
        disp = f'form-data; name="{name}"'
        if fn:
            disp += f'; filename="{fn}"'
        head = f'--{boundary}\r\nContent-Disposition: {disp}\r\n'
        if fn:
            head += f'Content-Type: {ct}\r\n'
        head += '\r\n'
        body = value if isinstance(value, bytes) else str(value).encode('utf-8')
        return head.encode('utf-8') + body + b'\r\n'

    payload = _part('chat_id', str(chat_id))
    if caption:
        payload += _part('caption', caption)
    payload += _part('document', file_bytes, fn=filename, ct=content_type)
    payload += f'--{boundary}--\r\n'.encode('utf-8')

    url = f'https://api.telegram.org/bot{_tg_token()}/sendDocument'
    req = urllib.request.Request(
        url, data=payload,
        headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
    try:
        urllib.request.urlopen(req, timeout=60)
        return True
    except Exception as e:                                   # noqa: BLE001
        if log:
            log.error("[addtools] sendDocument failed: %s", e)
        return False


# =============================================================================
#  Generic helpers
# =============================================================================
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _new_workdir() -> str:
    return tempfile.mkdtemp(prefix='addtools_')


def _cleanup(workdir: str):
    shutil.rmtree(workdir, ignore_errors=True)


def _menu_keyboard(chat_id=None) -> dict:
    """Build the inline keyboard (2 columns) + a back button."""
    rows, buf = [], []
    _is_adm = str(chat_id) in _LLM_ADMIN_IDS
    for label, name in TOOLS_MENU:
        if name in _ADMIN_ONLY_TOOLS and not _is_adm:
            continue
        btn = {'text': label, 'callback_data': f'tool:{name}'}
        if len(label) > 18:            # long label -> full-width row (no truncation)
            if buf:
                rows.append(buf); buf = []
            rows.append([btn])
        else:
            buf.append(btn)
            if len(buf) == 2:
                rows.append(buf)
                buf = []
    if buf:
        rows.append(buf)
    # Back -> MAIN menu via 'menu_back' (CB Router -> 'Menu Back Smart'), which
    # always renders the main menu regardless of active case. Using 'case_menu'
    # here was the bug: it hit 'Case Menu Render' and dead-ended with
    # "❌ Активний кейс не встановлений" when no case was set.
    # Admin-only master toggle for the LLM/GPU stack (brute-force mode).
    # LLM control buttons moved to the Admin menu (Адміністрування).
    rows.append([{'text': '⬅️ Назад', 'callback_data': 'menu_back'}])
    return {'inline_keyboard': rows}


def _set_pending(chat_id, user_id, tool, stage, **extra):
    PENDING[(str(chat_id), str(user_id))] = {
        'tool': tool, 'stage': stage, 'ts': time.time(), **extra}


def _get_pending(chat_id, user_id):
    st = PENDING.get((str(chat_id), str(user_id)))
    if st and (time.time() - st.get('ts', 0)) > PENDING_TTL:
        PENDING.pop((str(chat_id), str(user_id)), None)
        return None
    return st


def _clear_pending(chat_id, user_id):
    PENDING.pop((str(chat_id), str(user_id)), None)


# =============================================================================
#  Live-progress wrapper + LLM "what to do?" step  (task #19)
# -----------------------------------------------------------------------------
#  Mirrors app.py _heartbeat (~8284) and _gpu_busiest_pct (~7037), but lives in
#  THIS dependency-injected module (no app.py import). Self-contained Telegram
#  send/edit/delete over urllib (same RAW Bot API, no parse_mode).
#
#  CRITICAL ROUTING CONTRACT (verified against n8n):
#    * POST /addtools/message  -> timeout 290000 ms (file-upload path)
#    * POST /addtools/cb       -> timeout  30000 ms (callback path)
#  The "analyze->ASK->tap option" flow delivers the heavy work via a CALLBACK,
#  i.e. the 30 s /addtools/cb gate. OCR/translate can take far longer, so the
#  blocking work MUST NOT run inside the request thread or n8n would time the
#  node out at 30 s. _run_with_progress therefore runs work_fn() in a detached
#  daemon thread and returns immediately; the result is pushed to the user via
#  _tg_send_document (already how every tool delivers output), and a heartbeat
#  daemon animates an in-place status message until the work signals done.
# =============================================================================

# Per-tool ETA hints (seconds) for the asymptotic pseudo-bar / "~M с" estimate.
TOOL_TYPICAL_SEC = {
    'pdf_translate': 180,
    'transcribe': 120,
    'audio_clean': 240,
    'audio_translate_ua': 180,
    'book_mp3': 600,
    'img_enhance': 90,
    'img_plate': 120,
    'diarize': 180,
    'restore_faces': 90,
    'ocr':           90,
    'translate':     120,
    'bookidx_index':    600,
    'pdf_unlock':    15,
    'pdf_watermark': 20,
    'meta':          10,
}

# Tools that get an LLM-suggested "what to do?" step before running.
# NOTE: meta is intentionally NOT here. meta is sub-second and its only real
# parameter (full vs summary report) is not honoured by _do_meta; including it
# would (a) hit the sidecar /meta twice and (b) produce two identical options.
ASK_TOOLS = {'ocr', 'translate'}

# Only one live job per GPU slot per (chat,tool) at a time — guards double-tap.
# In the bot's 1:1 chats (one user per chat) this is equivalent to (chat,user).
_PROGRESS_BUSY: dict = {}
_PROGRESS_LOCK = threading.Lock()


def _tg_edit_msg(chat_id, message_id, text):
    """editMessageText (no parse_mode). Swallows 'message is not modified'."""
    token = _tg_token()
    if not token or not chat_id or not message_id or not text:
        return
    try:
        body = {'chat_id': str(chat_id), 'message_id': int(message_id), 'text': str(text)}
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{token}/editMessageText',
            data=json.dumps(body, ensure_ascii=False).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=12)
    except urllib.error.HTTPError as e:                       # noqa: BLE001
        try:
            eb = e.read().decode('utf-8', errors='ignore')[:300]
        except Exception:
            eb = ''
        if log and 'message is not modified' not in eb.lower():
            log.info("[addtools] edit failed: %s %s", getattr(e, 'code', '?'), eb)
    except Exception as e:                                    # noqa: BLE001
        if log:
            log.info("[addtools] edit failed: %s", e)


def _tg_delete_msg(chat_id, message_id):
    """deleteMessage — best effort, errors swallowed."""
    token = _tg_token()
    if not token or not chat_id or not message_id:
        return
    try:
        body = {'chat_id': str(chat_id), 'message_id': int(message_id)}
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{token}/deleteMessage',
            data=json.dumps(body).encode('utf-8'),
            headers={'Content-Type': 'application/json'}, method='POST')
        urllib.request.urlopen(req, timeout=12)
    except Exception:                                          # noqa: BLE001
        pass


def _gpu_busiest_pct_local():
    """Busiest-card GPU util % from the Windows agent /gpu/json, or None.
    Mirror of app._gpu_busiest_pct (app.py:7037). Fail-open: None if the agent
    URL/token were not injected or the agent is unreachable."""
    url = _CTX.get('WINDOWS_AGENT_URL')
    token = _CTX.get('WINDOWS_AGENT_TOKEN')
    try:
        if not (url and token):
            return None
        _rq = urllib.request.Request(url.rstrip('/') + '/gpu/json',
                                     headers={'X-DFIR-Token': token})
        _gj = json.loads(urllib.request.urlopen(_rq, timeout=4).read().decode())
        _utils = [g.get('util_pct') or 0 for g in _gj.get('gpus', [])]
        _u = max(_utils) if _utils else _gj.get('totals', {}).get('avg_util_pct')
        return int(_u) if _u is not None else None
    except Exception:                                         # noqa: BLE001
        return None


# _live_card_heartbeat_wired — additive progress-card plumbing.
# Lazy imports kept here so a missing symbol can never break tool execution.
_GPU_CACHE = {'ts': 0.0, 'val': None}
_GPU_CACHE_TTL = 4.0   # seconds; throttle :8788 reads so the heartbeat is cheap


def _gpu_busiest_pct_cached():
    """Cached wrapper around _gpu_busiest_pct_local(): at most one :8788 hit per
    _GPU_CACHE_TTL seconds. Fail-open to None; never raises."""
    try:
        now = time.time()
        if now - _GPU_CACHE['ts'] < _GPU_CACHE_TTL:
            return _GPU_CACHE['val']
        val = None
        try:
            val = _gpu_busiest_pct_local()
        except Exception:
            val = None
        _GPU_CACHE['ts'] = now
        _GPU_CACHE['val'] = val
        return val
    except Exception:
        return None


def _live_queue_stats():
    """Best-effort core.llm_queue.queue_stats(); {} on any failure."""
    try:
        from core.llm_queue import queue_stats as _qs
        return _qs() or {}
    except Exception:
        return {}


def _live_build_card(**kw):
    """Best-effort telegram.notify.build_live_card; returns None on failure so the
    caller can fall back to the legacy bar."""
    try:
        from telegram.notify import build_live_card as _blc
        return _blc(**kw)
    except Exception:
        return None


def _run_with_progress(chat_id, tool, label, work_fn, progress_path=None):
    """Send a status message, animate it (spinner + ▰▱ bar + elapsed + ETA + GPU%)
    every ~3 s on a daemon thread, and run work_fn() on ANOTHER daemon thread so
    the HTTP request that triggered us returns immediately (keeps the 30 s
    /addtools/cb gate happy). work_fn() pushes the real result itself (as today);
    when it returns we stop the heartbeat and delete the bar.

    Double-tap guard: only one live job per (chat,tool). A second concurrent tap
    is told the slot is busy and does NOT start a second GPU job."""
    key = (str(chat_id), tool)
    with _PROGRESS_LOCK:
        if _PROGRESS_BUSY.get(key):
            _send_plain(chat_id, "⏳ Цей інструмент уже працює — зачекайте на результат.")
            return
        _PROGRESS_BUSY[key] = True

    status_id = _send_plain(chat_id, f"{label}\n\n⠋  Запускаю…")
    state = {'stop': False, 't0': time.time()}
    spin = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    eta_total = TOOL_TYPICAL_SEC.get(tool, 60)

    def _heartbeat():
        i = 0
        while not state['stop']:
            if time.time() - state['t0'] > 21600:   # 6-hour cap (long audio lectures)
                break
            i += 1
            if status_id:
                el = int(time.time() - state['t0'])
                # Asymptotic pseudo-progress (no true %): approach 95%, never 100%
                # before the real result replaces/deletes this message.
                pct = int(100 * (1 - math.exp(-el / float(max(10, eta_total) / 2.0))))
                pct = max(3, min(95, pct))
                eta = max(0, eta_total - el)

                # ── ADDITIVE: render via build_live_card, fed by real stats. ──
                # Wrapped so a stats bug can NEVER stop the heartbeat / the work.
                text = None
                try:
                    qs = _live_queue_stats()
                    swapping = bool(qs.get('swapping'))
                    waiters = int(qs.get('waiters') or 0)
                    inflight = int(qs.get('inflight') or 0)
                    gpu = _gpu_busiest_pct_cached()

                    # SWAP MESSAGE: an LLM call is blocked while a model loads.
                    # Heuristic: queue reports a long-waiting request (swapping)
                    # and nothing is yet executing -> host is making room.
                    if swapping and inflight == 0:
                        text = _live_build_card(
                            op=tool, title=label, status='swap',
                            elapsed=el)
                    else:
                        queue_pos = None  # phantom-count fix: a RUNNING job is not in a queue; the global _waiters count (incl. our own chunks) misled single users into seeing В черзі: N
                        text = _live_build_card(
                            op=tool, title=label, status='running',
                            pct=pct, elapsed=el, eta=eta,
                            gpu=gpu, queue_pos=queue_pos)
                except Exception:
                    text = None
                if progress_path:
                    try:
                        _raw = open(progress_path).read().split()
                        _sd, _stot, _dur = int(_raw[0]), int(_raw[1]), int(_raw[2])
                        _mtot = max(_dur // 60, 1)
                        _mdone = (_sd * _dur // max(_stot, 1)) // 60
                        _pp = int(_sd * 100 / max(_stot, 1))
                        _bar = '▰' * (_pp // 10) + '▱' * (10 - _pp // 10)
                        text = (label + chr(10) + chr(10) + _bar + '  ' + str(_pp) + '%' + chr(10)
                                + '🎧 Сегмент ' + str(_sd) + '/' + str(_stot)
                                + '  ·  ~' + str(_mdone) + ' з ' + str(_mtot) + ' хв' + chr(10)
                                + '⏱ ' + str(el) + ' с')
                    except Exception:
                        pass

                if not text:
                    # ── Legacy fallback (unchanged behaviour). ──
                    filled = round(pct / 10.0)
                    bar = '▰' * filled + '▱' * (10 - filled)
                    gpu = _gpu_busiest_pct_cached()
                    meter = f"⏱ {el} с   ·   ⏳ ~{eta} с"
                    if gpu is not None:
                        meter += f"   ·   🎮 GPU {gpu}%"
                    text = (f"{label}\n\n{spin[i % len(spin)]}  Обробка…\n\n"
                            f"{bar}  {pct}%\n{meter}")

                _tg_edit_msg(chat_id, status_id, text)
            for _ in range(6):                      # ~3 s cadence
                if state['stop']:
                    break
                time.sleep(0.5)

    def _worker():
        try:
            work_fn()
        except Exception as e:                       # noqa: BLE001
            if log:
                log.error("[addtools] progress work failed (%s): %s", tool, e)
            try:
                _send_plain(chat_id, "❌ Помилка під час обробки.")
            except Exception:
                pass
        finally:
            state['stop'] = True
            if status_id:
                _tg_delete_msg(chat_id, status_id)
            with _PROGRESS_LOCK:
                _PROGRESS_BUSY.pop(key, None)

    threading.Thread(target=_heartbeat, daemon=True).start()
    threading.Thread(target=_worker, daemon=True).start()


# Static per-tool fallback menus (used when the LLM is unreachable / errors).
_ASK_FALLBACK = {
    'ocr': [
        {'label': '🇺🇦+🇬🇧 укр+англ', 'choice': 'ukr+eng'},
        {'label': '🇬🇧 англ', 'choice': 'eng'},
        {'label': '🇺🇦+🇬🇧+🇷🇺 укр+англ+рос', 'choice': 'ukr+eng+rus'},
    ],
    'translate': [
        {'label': '🇺🇦 Переклад українською', 'choice': 'ua'},
        {'label': '🇬🇧 Translate to English', 'choice': 'en'},
        {'label': '📄 Лише витягти текст', 'choice': 'extract'},
    ],
}


def _llm_suggest_actions(tool, meta_summary):
    """Ask the LOCAL gpt-oss (build_chat_payload -> LLM_URL) for up to 3
    {label,choice} options based ONLY on NON-PII derived metadata (never the
    document text). Falls back to a static per-tool menu on any error.

    `meta_summary` is a JSON STRING of derived fields (kind/pages/has_text/...);
    document CONTENT is never sent."""
    fallback = _ASK_FALLBACK.get(tool, [])
    valid = {o['choice'] for o in fallback}
    if not fallback:
        return fallback
    try:
        build_chat_payload = _CTX.get('build_chat_payload')
        llm_url_base = _CTX.get('LLM_URL')
        model = _CTX.get('LLM_MODEL')
        if not (build_chat_payload and llm_url_base and model):
            return fallback
        llm_url = llm_url_base.rstrip('/') + '/v1/chat/completions'
        allowed = ', '.join(sorted(valid))
        sys_msg = ("Ти — асистент DFIR-бота. На основі ЛИШЕ технічних метаданих "
                   "документа (без вмісту) обери найдоречніші дії для інструмента. "
                   "Поверни ЛИШЕ JSON-масив до 3 об'єктів {\"label\":<укр.текст>,"
                   "\"choice\":<один з дозволених кодів>}. Без коментарів.")
        usr_msg = (f"Інструмент: {tool}\n"
                   f"Дозволені choice-коди: {allowed}\n"
                   f"Метадані (НЕ вміст): {meta_summary}")
        body = json.dumps(build_chat_payload(
            model=model,
            messages=[
                {'role': 'system', 'content': sys_msg},
                {'role': 'user', 'content': usr_msg},
            ],
            role='fast',
            temperature=0.0,
            max_tokens=300,
            stream=False,
            reasoning_effort='low',
        )).encode('utf-8')
        req = urllib.request.Request(llm_url, data=body,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            rj = json.loads(r.read().decode('utf-8', errors='ignore'))
        content = (rj.get('choices') or [{}])[0].get('message', {}).get('content', '') or ''
        # tolerate fenced/extra text: pull the first [...] array
        m = re.search(r'\[.*\]', content, re.S)
        if not m:
            return fallback
        arr = json.loads(m.group(0))
        out = []
        for it in arr:
            if not isinstance(it, dict):
                continue
            ch = str(it.get('choice', '')).strip()
            lb = str(it.get('label', '')).strip()
            if ch in valid and lb:
                out.append({'label': lb[:60], 'choice': ch})
            if len(out) == 3:
                break
        return out or fallback
    except Exception as e:                                    # noqa: BLE001
        if log:
            log.info("[addtools] llm_suggest_actions fallback (%s): %s", tool, e)
        return fallback


def _ask_actions_keyboard(tool, options):
    """Inline keyboard. callback_data stays under the existing 'tool:' prefix so
    the n8n CB Router (startsWith 'tool:') routes it unchanged to /addtools/cb.
    Grammar: tool:act:<tool>:<choice>."""
    rows = []
    for o in (options or []):
        rows.append([{'text': o['label'],
                      'callback_data': f"tool:act:{tool}:{o['choice']}"}])
    rows.append([{'text': '⬅️ Назад', 'callback_data': 'addtools_menu'}])
    return {'inline_keyboard': rows}


# =============================================================================
#  Sidecar proxy
# =============================================================================
def _sidecar_post(endpoint: str, file_path: str, fields: dict | None = None, timeout: int | None = None):
    """POST a file (+ form fields) to the sidecar. Returns httpx.Response.
    `timeout` overrides the default SIDECAR_TIMEOUT (used for long audio jobs)."""
    with open(file_path, 'rb') as fh:
        files = {'file': (os.path.basename(file_path), fh.read())}
    with httpx.Client(timeout=(timeout or SIDECAR_TIMEOUT)) as client:
        return client.post(f'{SIDECAR_URL}{endpoint}', files=files, data=fields or {})


def _sidecar_err_message(resp) -> str:
    try:
        code = resp.json().get('error', 'process_failed')
    except Exception:
        code = 'process_failed'
    return SIDECAR_ERR_UA.get(code, "❌ Помилка обробки на сервері утиліт.")


# =============================================================================
#  SIDECAR TOOLS — download file, proxy, return result
# =============================================================================
def _do_pdf_unlock(chat_id, st):
    """Stage machine: await_file -> await_pw -> result."""
    workdir = st['workdir']
    def _work():
        resp = _sidecar_post('/pdf/unlock', st['file_path'], {'password': st.get('password', '')})
        _pdf_unlock_finish(chat_id, st, resp, workdir)
    _run_with_progress(chat_id, 'pdf_unlock', '🔓 Зняття пароля PDF', _work)


def _pdf_unlock_finish(chat_id, st, resp, workdir):
    if resp.status_code == 200:
        _tg_send_document(chat_id, resp.content,
                          (os.path.splitext(st['orig_name'])[0] or 'document') + '_decrypted.pdf',
                          caption="🔓 Пароль знято", content_type='application/pdf')
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    _cleanup(workdir)


def _do_pdf_translate(chat_id, st):
    """PDF -> translated PDF (EN->UK), layout preserved, via sidecar pdf2zh.
    Returns a SEPARATE *_ua.pdf working copy; the evidence original is untouched.
    Heavy work (pdf2zh + many small LLM calls) runs detached under the progress
    bar so the n8n /addtools/message request never blocks; the result is pushed
    out-of-band via _tg_send_document."""
    workdir = st['workdir']
    _pages = None  # page total for label (live per-page needs sidecar streaming)
    try:
        _m = _sidecar_post('/meta', st['file_path'])
        if _m.status_code == 200:
            _pages = (_m.json().get('meta') or {}).get('page_count')
    except Exception:
        _pages = None
    _lbl = '📄 Переклад PDF (сторінка+переклад поруч)' + (' · %d стор.' % _pages if _pages else '')
    def _work():
        resp = _sidecar_post('/pdf/translate-sbs', st['file_path'], {'password': st.get('password', '')})
        _pdf_translate_finish(chat_id, st, resp, workdir)
    _run_with_progress(chat_id, 'pdf_translate', _lbl, _work)


def _pdf_translate_finish(chat_id, st, resp, workdir):
    if resp.status_code == 200:
        base = os.path.splitext(st['orig_name'])[0] or 'document'
        # Формат визначає сайдкар: звичайно PDF, а для дуже великих книг - архів.
        fmt = (resp.headers.get('X-SBS-Format') or '').lower()
        if fmt == 'zip' or resp.headers.get('Content-Type', '').startswith('application/zip'):
            name, ctype = base + '_ua.zip', 'application/zip'
            caption = ("📄 Переклад готовий (EN→UK). Книга завелика для PDF, тому архів: "
                       "РОЗПАКУЙ його повністю і лише тоді відкривай index.html — "
                       "поруч має лежати тека img/, інакше замість сторінок будуть "
                       "значки «зображення не знайдено». Оригінал не змінено.")
        else:
            name, ctype = base + '_ua.pdf', 'application/pdf'
            caption = ("📄 Переклад готовий (EN→UK): ліворуч сторінка оригіналу, "
                       "праворуч переклад. Окрема копія, оригінал не змінено.")
        _tg_send_document(chat_id, resp.content, name, caption=caption,
                          content_type=ctype)
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    _cleanup(workdir)


def _do_pdf_watermark(chat_id, st):
    workdir = st['workdir']
    def _work():
        resp = _sidecar_post('/pdf/watermark', st['file_path'], {'text': st.get('text', '')})
        _pdf_watermark_finish(chat_id, st, resp, workdir)
    _run_with_progress(chat_id, 'pdf_watermark', '💧 Обробка водяного знака', _work)


def _pdf_watermark_finish(chat_id, st, resp, workdir):
    if resp.status_code == 200:
        _tg_send_document(chat_id, resp.content,
                          (os.path.splitext(st['orig_name'])[0] or 'document') + '_clean.pdf',
                          caption="💧 Водяний знак оброблено (робоча копія)",
                          content_type='application/pdf')
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    _cleanup(workdir)


def _do_ocr(chat_id, st):
    workdir = st['workdir']
    def _work():
        resp = _sidecar_post('/ocr', st['file_path'], {'lang': st.get('lang', 'ukr+eng')})
        _ocr_finish(chat_id, st, resp, workdir)
    _run_with_progress(chat_id, 'ocr', '🔎 OCR документа', _work)


def _ocr_finish(chat_id, st, resp, workdir):
    if resp.status_code == 200:
        _tg_send_document(chat_id, resp.content,
                          (os.path.splitext(st['orig_name'])[0] or 'document') + '_ocr.pdf',
                          caption="🔎 Готово: PDF з текстовим шаром",
                          content_type='application/pdf')
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    _cleanup(workdir)


def _do_yara(chat_id, st):
    """Scan an uploaded file with the local DFIR YARA ruleset (sidecar, offline)."""
    resp = _sidecar_post('/yara', st['file_path'])
    if resp.status_code == 200:
        d = resp.json()
        matches = d.get('matches', [])
        sha = (d.get('sha256', '') or '')[:32]
        if not matches:
            _send_plain(chat_id, "\U0001F9EC YARA: \u0447\u0438\u0441\u0442\u043e \u2014 \u0436\u043e\u0434\u043d\u0435 \u043f\u0440\u0430\u0432\u0438\u043b\u043e \u043d\u0435 \u0441\u043f\u0440\u0430\u0446\u044e\u0432\u0430\u043b\u043e.\nSHA256: %s\u2026" % sha)
        else:
            lines = ["\U0001F9EC YARA \u2014 \u0417\u041d\u0410\u0419\u0414\u0415\u041d\u041e %d \u0437\u0431\u0456\u0433(\u0456\u0432):" % len(matches), ""]
            for m in matches:
                lines.append("\U0001F534 %s [%s] %s" % (m.get('rule', ''), m.get('severity', ''), m.get('mitre', '')))
                if m.get('desc'):
                    lines.append("   " + str(m['desc']))
            lines.append("\nSHA256: %s\u2026" % sha)
            _send_plain(chat_id, "\n".join(lines)[:3800])
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    try:
        _cleanup(st['workdir'])
    except Exception:
        pass


def _do_meta(chat_id, st):
    workdir = st['workdir']
    resp = _sidecar_post('/meta', st['file_path'])
    if resp.status_code == 200:
        d = resp.json()
        report = d.get('report')
        if report:
            _send_plain(chat_id, ('🧬 ' + report)[:3800])
        else:
            lines = [f"🧬 Метадані ({d.get('kind')}) — *заявлені*, не є доказом:",
                     f"SHA256: {d.get('sha256', '')[:32]}…", ""]
            for k, v in (d.get('meta') or {}).items():
                if v in (None, '', {}):
                    continue
                lines.append(f"• {k}: {v}")
            _send_plain(chat_id, '\n'.join(lines)[:3800])
        # raw JSON as a sidecar file for the analyst
        raw = json.dumps(d, ensure_ascii=False, indent=2).encode('utf-8')
        _tg_send_document(chat_id, raw, f"{os.path.splitext(st['orig_name'])[0]}_meta.json",
                          content_type='application/json')
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
    _cleanup(workdir)


def _do_translate(chat_id, st):
    """Sidecar extracts text (native libs); the BOT's LLM does the translation."""
    label = '📄 Витяг тексту' if st.get('extract_only') else '🌐 Переклад документа'
    _run_with_progress(chat_id, 'translate', label,
                       lambda: _translate_work(chat_id, st))


def _translate_work(chat_id, st):
    workdir = st['workdir']
    resp = _sidecar_post('/translate/extract', st['file_path'])
    if resp.status_code != 200:
        _send_plain(chat_id, _sidecar_err_message(resp))
        _cleanup(workdir)
        return
    payload = resp.json()
    text = (payload.get('text') or '').strip()
    if not text:
        _send_plain(chat_id, "❌ Не вдалося витягти текст із документа.")
        _cleanup(workdir)
        return
    if payload.get('truncated'):
        _send_plain(chat_id, "ℹ️ Документ довгий — перекладаю першу частину.")

    # extract_only: deliver the raw extracted text, no LLM phase.
    if st.get('extract_only'):
        out = text.encode('utf-8')
        _tg_send_document(chat_id, out,
                          f"{os.path.splitext(st['orig_name'])[0]}_extracted.txt",
                          caption="📄 Витягнутий текст — окрема копія, оригінал не змінено.",
                          content_type='text/plain')
        _cleanup(workdir)
        return

    target = st.get('target', 'українською')
    translated = _llm_translate(text, target)
    if not translated:
        _send_plain(chat_id, "❌ LLM не повернула переклад.")
        _cleanup(workdir)
        return
    out = translated.encode('utf-8')
    _tg_send_document(chat_id, out,
                      f"{os.path.splitext(st['orig_name'])[0]}_translated.txt",
                      caption=f"🌐 Переклад ({target}) — окрема копія, оригінал не змінено.",
                      content_type='text/plain')
    _cleanup(workdir)


def _llm_translate(text: str, target: str) -> str:
    """Chunk + PARALLEL translate via a fast dedicated model (Gemma by default),
    with deterministic glossary protection so key DFIR terms survive verbatim.
    Chunks dispatched concurrently and reassembled in order. On-prem, no egress."""
    import concurrent.futures as _cf, re as _re
    llm_url = os.getenv('DFIR_TOOLS_TRANSLATE_URL', _CTX['LLM_URL']).rstrip('/') + '/v1/chat/completions'
    model = os.getenv('DFIR_TOOLS_TRANSLATE_MODEL', 'translate-9b')
    parallel = max(1, int(os.getenv('DFIR_TOOLS_TRANSLATE_PARALLEL', '4')))
    chunk_chars = int(os.getenv('DFIR_TOOLS_TRANSLATE_CHUNK', '2500'))
    max_chunks = int(os.getenv('DFIR_TOOLS_TRANSLATE_MAX_CHUNKS', '40'))
    max_tokens = int(os.getenv('DFIR_TOOLS_TRANSLATE_MAX_TOKENS', '2000'))
    _default_gloss = ('persistence,obfuscated,obfuscation,dropper,payload,beacon,beaconing,'
                      'lateral movement,privilege escalation,credential dumping,exfiltration,'
                      'command and control,living off the land,prefetch,amcache,shimcache,'
                      'appcompatcache,lsass,mimikatz,powershell,sysmon,scheduled task,run key')
    glossary = [t.strip() for t in os.getenv('DFIR_TOOLS_TRANSLATE_GLOSSARY', _default_gloss).split(',') if t.strip()]
    glossary.sort(key=len, reverse=True)
    chunks = [text[i:i + chunk_chars] for i in range(0, len(text), chunk_chars)][:max_chunks]
    if not chunks:
        return ''
    sys_prompt = ('Ти - професійний перекладач DFIR-документів. Перекладай природною '
                  'українською. Токени-плейсхолдери виду [[N]] копіюй БЕЗ ЗМІН. '
                  'Зберігай форматування, IOC, шляхи, EventID, хеші, порти, домени.')
    _pat = _re.compile(r'(?<!\w)(' + '|'.join(_re.escape(t) for t in glossary) + r')(?!\w)', _re.I) if glossary else None

    def _one(item):
        idx, chunk = item
        store = []
        if _pat is not None:
            def _prot(m):
                store.append(m.group(0))
                return '[[%d]]' % (len(store) - 1)
            src = _pat.sub(_prot, chunk)
        else:
            src = chunk
        prompt = ('Переклади наведений текст %s. Поверни ЛИШЕ переклад без коментарів.\n\n%s' % (target, src))
        payload = {'model': model,
                   'messages': [{'role': 'system', 'content': sys_prompt},
                                {'role': 'user', 'content': prompt}],
                   'temperature': 0.1, 'max_tokens': max_tokens, 'stream': False}
        if 'gpt-oss' in model:
            payload['reasoning_effort'] = 'low'
        body = json.dumps(payload).encode('utf-8')
        try:
            req = urllib.request.Request(llm_url, data=body, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=300) as r:
                rj = json.loads(r.read().decode('utf-8', errors='ignore'))
            out = (rj.get('choices') or [{}])[0].get('message', {}).get('content', '').strip()
            for k in range(len(store) - 1, -1, -1):
                out = out.replace('[[%d]]' % k, store[k])
            return idx, out
        except Exception as e:                               # noqa: BLE001
            if log:
                log.error("[addtools] translate chunk %d failed: %s", idx, e)
            return idx, ('[chunk %d translation failed]' % idx)

    results = [''] * len(chunks)
    with _cf.ThreadPoolExecutor(max_workers=min(parallel, len(chunks))) as ex:
        for idx, piece in ex.map(_one, list(enumerate(chunks))):
            results[idx] = piece
    return '\n\n'.join(results).strip()


# =============================================================================
#  INLINE TOOLS — pure-python, run in the Alpine container directly
# =============================================================================
def _do_hash(chat_id, st):
    """MD5 / SHA1 / SHA256 of an uploaded file (streamed, never fully in RAM)."""
    workdir = st['workdir']
    md5 = hashlib.md5()      # noqa: S324  (forensic identity, not security)
    sha1 = hashlib.sha1()    # noqa: S324
    sha256 = hashlib.sha256()
    size = 0
    with open(st['file_path'], 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            size += len(chunk)
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    msg = (f"#️⃣ Хеші файлу: {st['orig_name']} ({size} байт)\n\n"
           f"MD5:    {md5.hexdigest()}\n"
           f"SHA1:   {sha1.hexdigest()}\n"
           f"SHA256: {sha256.hexdigest()}")
    # VirusTotal single-hash button removed pre-launch: it was a dead callback
    # (no route) and needs VIRUSTOTAL_API_KEY (unset). Case-level /ioc-enrich VT
    # path stays available once a key is configured.
    _send_plain(chat_id, msg)
    _cleanup(workdir)


# --- Defang / Refang ---------------------------------------------------------
def _defang(text: str) -> str:
    out = text
    out = re.sub(r'https?(?=://)', lambda m: m.group(0).replace('tt', 'xx').replace('TT', 'XX'), out, flags=re.I)
    out = out.replace('://', '[://]')
    out = re.sub(r'\.(?=\w)', '[.]', out)
    out = out.replace('@', '[at]')
    return out


def _refang(text: str) -> str:
    out = text
    out = out.replace('[://]', '://').replace('[.]', '.').replace('[at]', '@')
    # hxxp / hxxps / HXXP / HXXPS -> http(s), preserving the original case.
    out = re.sub(r'hxxp(s?)',
                 lambda m: ('HTTP' if m.group(0).isupper() else 'http') + m.group(1),
                 out, flags=re.I)
    return out


def _looks_defanged(text: str) -> bool:
    return '[.]' in text or 'hxxp' in text.lower() or '[at]' in text or '[://]' in text


def _do_defang(chat_id, st):
    text = st.get('text', '')
    if _looks_defanged(text):
        result = _refang(text); mode = "refang (бойовий вигляд)"
    else:
        result = _defang(text); mode = "defang (безпечний вигляд)"
    _send_plain(chat_id, f"🛡 {mode}:\n\n{result[:DECODE_OUTPUT_CAP]}")
    _clear_pending_from_state(chat_id, st)


# --- Multi-decode ------------------------------------------------------------
def _try_decode(s: str):
    """Try a battery of decoders; return list of (codec, decoded_preview)."""
    results = []
    raw = s.strip()
    # base64 (incl. PowerShell -EncodedCommand = base64 of UTF-16LE)
    try:
        b = base64.b64decode(raw + '=' * (-len(raw) % 4), validate=False)
        results.append(('base64 (utf-8)', b.decode('utf-8', errors='replace')))
        try:
            results.append(('base64 (utf-16le / PowerShell)', b.decode('utf-16-le', errors='replace')))
        except Exception:
            pass
    except Exception:
        pass
    # hex
    try:
        h = binascii.unhexlify(re.sub(r'\s+', '', raw))
        results.append(('hex', h.decode('utf-8', errors='replace')))
    except Exception:
        pass
    # URL-encoding
    if '%' in raw:
        results.append(('url', urllib.parse.unquote(raw)))
    # gzip / zlib (input must be bytes-ish; try from base64 first then raw latin1)
    for label, data in (('gzip', None), ('zlib', None)):
        try:
            blob = base64.b64decode(raw + '=' * (-len(raw) % 4)) if _is_b64(raw) else raw.encode('latin1')
            dec = gzip.decompress(blob) if label == 'gzip' else zlib.decompress(blob)
            results.append((label, dec.decode('utf-8', errors='replace')))
        except Exception:
            pass
    # ROT13
    try:
        import codecs
        results.append(('rot13', codecs.decode(raw, 'rot_13')))
    except Exception:
        pass
    return results


def _is_b64(s: str) -> bool:
    return bool(re.fullmatch(r'[A-Za-z0-9+/=\s]+', s or '')) and len(s.strip()) % 4 in (0, 2, 3)


def _do_decode(chat_id, st):
    text = st.get('text', '')
    found = _try_decode(text)
    if not found:
        _send_plain(chat_id, "🔁 Не вдалося розпізнати кодування.")
    else:
        out = ["🔁 Результати декодування (показано застосований трансформ):"]
        for codec, val in found[:6]:
            preview = val[:1500]
            out.append(f"\n— {codec} —\n{preview}")
        _send_plain(chat_id, '\n'.join(out)[:DECODE_OUTPUT_CAP])
    _clear_pending_from_state(chat_id, st)


# --- IOC extraction (reuses the repo's regex philosophy; standalone here) -----
_IOC_PATTERNS = {
    'ipv4':   re.compile(r'\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b'),
    'url':    re.compile(r'\b(?:h[xX]?[tT]{1,2}[pP]s?|hxxps?)\[?:?//?[^\s<>"]+', re.I),
    'domain': re.compile(r'\b(?:[a-z0-9-]+\[?\.\]?)+[a-z]{2,}\b', re.I),
    'email':  re.compile(r'\b[A-Za-z0-9._%+-]+(?:@|\[@\]|\(at\)|\[at\])[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'md5':    re.compile(r'\b[a-f0-9]{32}\b', re.I),
    'sha1':   re.compile(r'\b[a-f0-9]{40}\b', re.I),
    'sha256': re.compile(r'\b[a-f0-9]{64}\b', re.I),
    'cve':    re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I),
}
_PRIVATE_IP = re.compile(r'^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.)')


def _do_iocextract(chat_id, st):
    text = _refang(st.get('text', ''))   # normalise defanged input first
    grouped = {}
    for kind, pat in _IOC_PATTERNS.items():
        hits = sorted({m.group(0) for m in pat.finditer(text)})
        if kind == 'ipv4':
            hits = [h for h in hits if not _PRIVATE_IP.match(h)]
        if hits:
            grouped[kind] = hits
    if not grouped:
        _send_plain(chat_id, "🎯 IOC не знайдено.")
    else:
        lines = ["🎯 Знайдені IOC (defanged, для безпечного копіювання):", ""]
        for kind, hits in grouped.items():
            lines.append(f"[{kind}] ({len(hits)})")
            for h in hits[:50]:
                lines.append("  " + _defang(h))
            lines.append("")
        _send_plain(chat_id, '\n'.join(lines)[:DECODE_OUTPUT_CAP])
        raw = json.dumps(grouped, ensure_ascii=False, indent=2).encode('utf-8')
        _tg_send_document(chat_id, raw, "iocs.json", content_type='application/json')
    _clear_pending_from_state(chat_id, st)


# --- Email (EML stdlib; MSG via extract-msg if installable) ------------------
# --- Safe HTML sanitizer (stdlib only; no bleach, no egress) -----------------
_HTML_ALLOWED_TAGS = {
    'a','b','i','u','em','strong','p','br','hr','div','span','blockquote',
    'ul','ol','li','dl','dt','dd','table','thead','tbody','tfoot','tr','td','th',
    'h1','h2','h3','h4','h5','h6','pre','code','sub','sup','small','center','font',
    'caption','col','colgroup','img',
}
_HTML_ALLOWED_ATTRS = {
    'a': {'href', 'title'},
    'img': {'alt', 'title', 'width', 'height'},  # NOTE: src is deliberately dropped
    'td': {'colspan', 'rowspan', 'align', 'valign'},
    'th': {'colspan', 'rowspan', 'align', 'valign'},
    'col': {'span', 'align'},
    'colgroup': {'span', 'align'},
    'font': {'color'},
    'div': set(), 'span': set(), 'p': set(),
}
_HTML_VOID = {'br', 'hr', 'img', 'col'}


class _SafeHTMLSanitizer(HTMLParser):
    """Whitelist sanitizer. Strips script/style/iframe/object, all event
    handlers, javascript:/data: URLs, remote image src (blocks tracking
    pixels / beacons), and CSS. Output is a self-contained, inert fragment."""

    # Container drop tags: they HAVE an end tag, so we skip the whole subtree
    # via _skip_depth (incremented on start, decremented on the matching end).
    _DROP_SUBTREE = {'script', 'style', 'iframe', 'object', 'embed',
                     'applet', 'form', 'svg', 'math',
                     'template', 'noscript', 'title', 'head'}
    # Standalone/void drop tags: they have NO end tag (meta/link/base). They
    # must be dropped WITHOUT touching _skip_depth -- otherwise a normal email
    # with <head><meta ...></head> would leave _skip_depth>0 forever and blank
    # the entire body (the bug this fix addresses).
    _DROP_VOID = {'meta', 'link', 'base'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self._skip_depth = 0          # inside a dropped subtree (script/style)
        self.ext_links = []           # collected href targets for the report
        self.remote_imgs = []         # collected stripped image srcs (trackers)

    @staticmethod
    def _safe_url(url):
        u = (url or '').strip()
        low = u.lower().replace('\t', '').replace('\n', '').replace('\r', '')
        if low.startswith(('javascript:', 'data:', 'vbscript:', 'file:', 'about:')):
            return None
        return u

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self._DROP_VOID:        # meta/link/base -> drop, no subtree
            return
        if tag in self._DROP_SUBTREE:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag not in _HTML_ALLOWED_TAGS:
            return
        allowed = _HTML_ALLOWED_ATTRS.get(tag, set())
        kept = []
        for k, v in attrs:
            k = (k or '').lower()
            if k.startswith('on'):            # event handler -> drop
                continue
            if tag == 'a' and k == 'href':
                su = self._safe_url(v)
                if su:
                    self.ext_links.append(su)
                    kept.append((k, su))
                continue
            if tag == 'img' and k == 'src':   # remote image -> strip (anti-beacon)
                if v:
                    self.remote_imgs.append(v)
                continue
            if k == 'style':                  # CSS can carry url()/expression()
                continue
            if k in allowed:
                kept.append((k, v))
        attr_s = ''.join(
            ' %s="%s"' % (k, html.escape(v or '', quote=True)) for k, v in kept)
        if tag == 'a':
            attr_s += ' rel="noopener noreferrer nofollow" target="_blank"'
        if tag in _HTML_VOID:
            self.out.append('<%s%s>' % (tag, attr_s))
        else:
            self.out.append('<%s%s>' % (tag, attr_s))

    def handle_startendtag(self, tag, attrs):
        # Self-closing form, e.g. <meta .../> or <br/>. A self-closing tag can
        # never open a subtree, so it must NOT touch _skip_depth. Drop-tags are
        # discarded; everything else is treated as a plain start tag.
        tag = tag.lower()
        if tag in self._DROP_VOID or tag in self._DROP_SUBTREE:
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self._DROP_VOID:        # void drop tags never open a subtree
            return
        if tag in self._DROP_SUBTREE:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag in _HTML_ALLOWED_TAGS and tag not in _HTML_VOID:
            self.out.append('</%s>' % tag)

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.out.append(html.escape(data))

    def result(self):
        return ''.join(self.out)


def _build_eml_preview_html(meta, html_body, text_body):
    """Wrap sanitized message HTML in a standalone, inert document with a
    forensic header banner. Returns (full_html_bytes, ext_links, remote_imgs)."""
    ext_links, remote_imgs = [], []
    if html_body:
        san = _SafeHTMLSanitizer()
        try:
            san.feed(html_body)
            san.close()
        except Exception:                                   # noqa: BLE001
            pass
        body_html = san.result()
        ext_links = san.ext_links
        remote_imgs = san.remote_imgs
    else:
        body_html = '<pre>%s</pre>' % html.escape(text_body or '(порожнє тіло)')

    def esc(x):
        return html.escape(str(x or ''))

    banner_rows = ''.join(
        '<tr><td class="k">%s</td><td class="v">%s</td></tr>' % (esc(k), esc(v))
        for k, v in [
            ('From', meta.get('from')), ('To', meta.get('to')),
            ('Subject', meta.get('subject')), ('Date', meta.get('date')),
            ('Reply-To', meta.get('reply_to')),
            ('Message-ID', meta.get('message_id')),
        ] if v)

    note = ''
    if remote_imgs:
        note = ('<div class="note">⚠ Заблоковано %d віддалених зображень '
                '(потенційні tracking-пікселі). src видалено.</div>'
                % len(remote_imgs))

    doc = (
        '<!DOCTYPE html><html lang="uk"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; '
        'font-src data:;">'
        '<meta name="referrer" content="no-referrer">'
        '<title>EML preview — %(subj)s</title>'
        '<style>body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;'
        'background:#f5f5f5;color:#222}.hdr{background:#fff;border-bottom:2px solid #d33;'
        'padding:12px 16px}.hdr h1{font-size:14px;margin:0 0 8px;color:#d33}'
        '.hdr table{font-size:12px;border-collapse:collapse}.hdr td{padding:1px 6px;'
        'vertical-align:top}.hdr td.k{color:#666;font-weight:bold;white-space:nowrap}'
        '.hdr td.v{color:#111;word-break:break-all}.note{color:#a50;font-size:12px;'
        'margin-top:6px}.bodywrap{background:#fff;margin:12px;padding:16px;'
        'border:1px solid #ddd;border-radius:4px;overflow:auto}'
        'a{color:#06c}img{max-width:100%%}</style></head><body>'
        '<div class="hdr"><h1>\U0001f512 EML SAFE PREVIEW — скрипти/стилі/віддалені ресурси вимкнено</h1>'
        '<table>%(rows)s</table>%(note)s</div>'
        '<div class="bodywrap">%(body)s</div></body></html>'
    ) % {'subj': esc(meta.get('subject')), 'rows': banner_rows,
         'note': note, 'body': body_html}
    return doc.encode('utf-8'), ext_links, remote_imgs


_EML_AUTHORITY_RE = re.compile(
    r'держ|поліц|нотар|суд\b|прокурат|податк|казнач|міністерств|мвс|сбу|'
    r'національн|обласн|управлінн|департамент|адміністрац|банк|казна|митн|'
    r'пенсійн|соціальн|ministr|police|court|tax|government|gov\b', re.I)
_EML_FILESHARE_RE = re.compile(
    r'swisstransfer|wetransfer|we\.tl|dropbox|mega\.nz|mediafire|mega\.io|'
    r'drive\.google|docs\.google|onedrive|1drv\.ms|sendspace|file\.io|'
    r'gofile|pixeldrain|dropmefiles|uploadfiles|anonfiles|filebin|ufile', re.I)
_EML_DANGER_EXT_RE = re.compile(
    r'\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|jar|msi|msix|ps1|'
    r'lnk|iso|img|vhd|reg|cpl|dll|apk|ace|arj)(\s|$)', re.I)


def _eml_domain(addr):
    """Registrable-ish domain from an address/URL host (lowercased)."""
    s = str(addr or '').lower()
    m = re.search(r'@([a-z0-9.\-]+)', s) or re.search(r'https?://([a-z0-9.\-]+)', s) \
        or re.search(r'\b([a-z0-9\-]+\.[a-z]{2,})\b', s)
    if not m:
        return ''
    host = m.group(1).strip('.')
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host) or ':' in host:
        return host   # bare IP literal -> do NOT registrable-truncate
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    sld = {'com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'in', 'mil'}
    if parts[-2] in sld and len(parts[-1]) == 2:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def _eml_ioc_crossref(values):
    """Do any of these IOC values (IPs/domains/URL-hosts) appear in an existing
    case? Returns a list of (value, ioc_type, [case_keys]). This is the killer
    signal — it links a fresh email to a KNOWN campaign in our case DB."""
    vals = sorted({str(v).lower().strip() for v in values if v and len(str(v)) > 3})
    if not vals:
        return []
    out = []
    try:
        import psycopg2
        from core.config import PG_DSN
        with psycopg2.connect(PG_DSN) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout = '8s'")
                for v in vals[:25]:
                    cur.execute(
                        "SELECT DISTINCT case_key, ioc_type FROM case_iocs "
                        "WHERE lower(ioc_value)=%s OR lower(ioc_norm)=%s "
                        "OR lower(ioc_value) LIKE %s LIMIT 8",
                        (v, v, '%' + v + '%'))
                    rows = cur.fetchall()
                    if rows:
                        cks = sorted({r[0] for r in rows})
                        it = rows[0][1]
                        out.append((v, it, cks))
    except Exception as e:                                  # noqa: BLE001
        if log:
            log.warning('[eml xref] %s', repr(e)[:120])
    return out


def _eml_forensics(meta, ext_links, attachments):
    """Deterministic forensic pre-analysis of an email — the GROUND TRUTH fed to
    the LLM so it reasons over facts, not guesses. Returns (facts_text, flags[])."""
    flags = []
    from_raw = str(meta.get('from', ''))
    disp = re.sub(r'<[^>]*>', '', from_raw).strip().strip('"').strip()
    from_dom = _eml_domain(from_raw)
    reply_dom = _eml_domain(meta.get('reply_to', ''))
    ret_dom = _eml_domain(meta.get('return_path', ''))
    mid_dom = _eml_domain(meta.get('message_id', ''))

    auth = str(meta.get('auth_results', '')) + ' ' + str(meta.get('received_spf', ''))
    def _av(kind):
        m = re.search(kind + r'\s*=\s*([a-z]+)', auth, re.I)
        return (m.group(1).lower() if m else '?')
    spf, dkim, dmarc = _av('spf'), _av('dkim'), _av('dmarc')
    dkim_d = (re.search(r'dkim=[a-z]+[^;]*?header\.i=@?([a-z0-9.\-]+)', auth, re.I)
              or re.search(r'\bd=([a-z0-9.\-]+)', auth, re.I))
    dkim_d = _eml_domain(dkim_d.group(1)) if dkim_d else ''
    dmarc_p = re.search(r'dmarc=[a-z]+\s*\(p=([a-z]+)', auth, re.I)
    dmarc_p = dmarc_p.group(1).lower() if dmarc_p else '?'
    spf_ip = re.search(r'designates\s+([0-9a-f:.]+)\s+as', auth, re.I)
    spf_ip = spf_ip.group(1) if spf_ip else ''

    # public IPs across received + auth
    ipv4 = re.findall(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])',
                      ' '.join(meta.get('received') or []) + ' ' + auth)
    def _pub(ip):
        return not re.match(r'^(10\.|127\.|0\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|255\.)', ip)
    pub_ips = sorted({ip for ip in ipv4 if _pub(ip)})

    recv = meta.get('received') or []
    origin_ip = pub_ips[0] if pub_ips else ''
    mta = ', '.join(sorted(set(re.findall(r'\b(Haraka|Postfix|Exim|Sendmail|Microsoft SMTP|qmail|OpenSMTPD)\S*', ' '.join(recv), re.I))))
    localhost_origin = bool(re.search(r'from\s+localhost|127\.0\.0\.1', ' '.join(recv), re.I))

    # timezone anomaly: injection tz vs Date tz
    date_tz = re.search(r'([+\-]\d{4})\s*$', str(meta.get('date', '')).strip())
    inj_tz = re.findall(r'([+\-]\d{4})\s*\(', ' '.join(recv)) or re.findall(r'\(([A-Z]{2,4})\)', ' '.join(recv))

    # ── alignment / spoof reasoning ──
    doms = {d for d in [from_dom, reply_dom, ret_dom, dkim_d] if d}
    if from_dom and dkim_d and from_dom != dkim_d:
        flags.append('DKIM d=%s НЕ збігається з доменом From %s (аліgit-fail / чужий підпис)' % (dkim_d, from_dom))
    if from_dom and mid_dom and from_dom != mid_dom:
        flags.append('Message-ID видано доменом %s, а не доменом відправника %s (лист згенеровано на чужому сервері)' % (mid_dom, from_dom))
    if reply_dom and from_dom and reply_dom != from_dom:
        flags.append('Reply-To (%s) відрізняється від From (%s)' % (reply_dom, from_dom))
    if dkim == 'fail':
        flags.append('DKIM=fail — цифровий підпис не пройшов перевірку')
    if dmarc_p in ('none', '?'):
        flags.append('DMARC політика p=%s — НЕ блокує підроблені листи (немає примусу)' % dmarc_p)
    if _EML_AUTHORITY_RE.search(disp) and from_dom:
        cc = from_dom.rsplit('.', 1)[-1]
        if cc not in ('ua',) and not from_dom.endswith('.gov.ua'):
            flags.append('Ім\'я відправника видає держ/офіційну установу («%s»), але домен %s — НЕ український/офіційний (імперсонація авторитету)' % (disp[:60], from_dom))
    if localhost_origin:
        flags.append('Лист впорснуто з localhost/127.0.0.1 через authenticated submission — не звичайний MTA-ланцюг')
    if date_tz and inj_tz and isinstance(inj_tz[0], str) and inj_tz[0].startswith(('+', '-')) and date_tz.group(1) != inj_tz[0]:
        flags.append('Часовий пояс відправлення (%s у Received) не збігається з Date (%s)' % (inj_tz[0], date_tz.group(1)))

    # ── URLs ──
    url_hosts = []
    fileshare = []
    ip_urls = []
    idn = []
    for u in (ext_links or []) + (meta.get('links') or []):
        h = _eml_domain(u)
        if h:
            url_hosts.append(h)
        if _EML_FILESHARE_RE.search(u):
            fileshare.append(h or u)
        if re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', u):
            ip_urls.append(u)
        if 'xn--' in u.lower():
            idn.append(h or u)
    url_hosts = sorted(set(url_hosts))
    if fileshare:
        flags.append('Посилання на файлообмінник (%s) — типовий обхід антивірусних шлюзів для доставки навантаження' % ', '.join(sorted(set(fileshare))[:3]))
    if ip_urls:
        flags.append('URL із голою IP-адресою (%d) — сильний фішинг-індикатор' % len(ip_urls))
    if idn:
        flags.append('IDN/punycode-домен (%s) — можливий homoglyph-typosquat' % ', '.join(idn[:3]))

    # ── attachments ──
    danger = []
    for n, _b in (attachments or []):
        if _EML_DANGER_EXT_RE.search(n or ''):
            danger.append(n)
        if len(re.findall(r'\.[a-z0-9]{2,4}', (n or '').lower())) >= 2 and re.search(r'\.(pdf|doc|docx|jpg|png|xls|xlsx)\.[a-z]{2,4}$', (n or '').lower()):
            danger.append(n + ' (подвійне розширення)')
    if danger:
        flags.append('Небезпечні вкладення: %s' % ', '.join(danger[:5]))

    # ── IOC cross-reference against known cases ──
    xref = _eml_ioc_crossref(pub_ips + list(doms) + url_hosts)

    # ── assemble ground-truth facts block ──
    L = ['ДЕТЕРМІНОВАНІ ФАКТИ (перевірено кодом, не вигадуй інше):']
    L.append('• Домени: From=%s | Reply-To=%s | Return-Path=%s | Message-ID=%s | DKIM d=%s'
             % (from_dom or '-', reply_dom or '-', ret_dom or '-', mid_dom or '-', dkim_d or '-'))
    L.append('• Автентифікація: SPF=%s DKIM=%s DMARC=%s (політика p=%s)%s'
             % (spf, dkim, dmarc, dmarc_p, (' | SPF авторизує IP %s' % spf_ip) if spf_ip else ''))
    if pub_ips:
        L.append('• Публічні IP у ланцюгу: %s' % ', '.join(pub_ips[:6]))
    if origin_ip:
        L.append('• Ймовірний IP-джерело: %s%s' % (origin_ip, (' | MTA: %s' % mta) if mta else ''))
    L.append('• Received-хопів: %d%s' % (len(recv), ' | старт із localhost (authenticated submission)' if localhost_origin else ''))
    if url_hosts:
        L.append('• Хости посилань: %s' % ', '.join(url_hosts[:8]))
    if xref:
        L.append('• ⚠️ ЗБІГ З ІСНУЮЧИМИ КЕЙСАМИ (той самий IOC уже фігурує):')
        for v, it, cks in xref[:8]:
            L.append('    – %s (%s) → кейси: %s' % (v, it, ', '.join(cks)))
        flags.append('IOC цього листа ВЖЕ Є у наших кейсах (%s) — ймовірно та сама кампанія/актор' % '; '.join('%s→%s' % (v, ','.join(c)) for v, _, c in xref[:4]))
    if flags:
        L.append('АВТОМАТИЧНІ ЧЕРВОНІ ПРАПОРЦІ:')
        for f in flags:
            L.append('  ⚑ ' + f)
    return '\n'.join(L), flags


def _eml_llm_analysis(meta, text_body, ext_links, attachments):
    """Local-LLM phishing/header/auth analysis. Mirrors _llm_translate plumbing:
    build_chat_payload + urllib POST to the on-prem gpt-oss endpoint. No egress."""
    try:
        build_chat_payload = _CTX['build_chat_payload']
        llm_url = _CTX['LLM_URL'].rstrip('/') + '/v1/chat/completions'
        model = os.getenv('DFIR_EML_MODEL', 'gemma-4-31b')  # capable resident; no gpt-oss empty-content
    except Exception:                                       # noqa: BLE001
        return None

    # deterministic forensic ground-truth (auth parse, alignment, IOC cross-ref)
    try:
        forensic_facts, _flags = _eml_forensics(meta, ext_links, attachments)
    except Exception as e:                                  # noqa: BLE001
        if log:
            log.warning('[eml forensics] %s', repr(e)[:150])
        forensic_facts = ''

    links_s = '\n'.join('- ' + l for l in ext_links[:40]) or '(немає)'
    atts_s = '\n'.join('- %s' % n for n, _ in attachments[:20]) or '(немає)'
    facts = (
        (forensic_facts + "\n\n" if forensic_facts else "")
        + "СИРІ ЗАГОЛОВКИ:\n"
        f"From: {meta.get('from','')}\n"
        f"Reply-To: {meta.get('reply_to','')}\n"
        f"Return-Path: {meta.get('return_path','')}\n"
        f"To: {meta.get('to','')}\n"
        f"Subject: {meta.get('subject','')}\n"
        f"Date: {meta.get('date','')}\n"
        f"Message-ID: {meta.get('message_id','')}\n"
        f"Authentication-Results: {meta.get('auth_results','')}\n"
        f"Received-SPF: {meta.get('received_spf','')}\n"
        f"X-Mailer: {meta.get('x_mailer','')}\n"
        f"Received-ланцюг ({len(meta.get('received') or [])}):\n"
        + '\n'.join('  ' + r for r in (meta.get('received') or [])[:8]) + "\n\n"
        f"ПОСИЛАННЯ В ТІЛІ:\n{links_s}\n\n"
        f"ВКЛАДЕННЯ:\n{atts_s}\n\n"
        f"ФРАГМЕНТ ТІЛА (text):\n{(text_body or '')[:3000]}"
    )
    system = (
        "Ти — провідний DFIR/CTI-аналітик електронної пошти рівня SOC Tier-3. "
        "Тобі надано ДЕТЕРМІНОВАНІ ФАКТИ (перевірені кодом — автентифікація, вирівнювання "
        "доменів, IOC-крос-звірка з нашими кейсами) та сирі заголовки. Спирайся НАСАМПЕРЕД на "
        "детерміновані факти; сирі дані — для деталізації. Не вигадуй значень SPF/DKIM/DMARC — "
        "бери їх із фактів. Відповідай українською, професійно, конкретно, БЕЗ води.\n\n"
        "Формат відповіді (рівно ці розділи):\n"
        "1) ⚖️ ВЕРДИКТ: рівень (Низький/Середній/Високий/Критичний) + впевненість (%) + 1–2 речення суті.\n"
        "2) 🔐 АВТЕНТИФІКАЦІЯ Й ВИРІВНЮВАННЯ: розбери SPF/DKIM/DMARC простими словами (що означає "
        "кожен результат для отримувача), вирівнювання From vs Return-Path/Reply-To/DKIM d=/Message-ID; "
        "поясни, ЧОМУ DMARC p=none небезпечний.\n"
        "3) 🌐 ІНФРАСТРУКТУРА: IP-джерело, MTA, країна/невідповідність, аномалії Received (localhost-впорск, "
        "часові пояси), домен-невідповідності.\n"
        "4) 🔗 ПОСИЛАННЯ/ВКЛАДЕННЯ: display vs реальний домен, файлообмінники як спосіб доставки, IP-URL, "
        "IDN/typosquat, небезпечні розширення. НЕ переходь за посиланнями. Defang усі IOC (hxxp, [.]).\n"
        "5) 🧩 ЗВ'ЯЗОК ІЗ КЕЙСАМИ: якщо у фактах є збіг IOC з існуючими кейсами — ЯВНО назви це головним "
        "висновком (та сама кампанія/актор) і перелічи кейси. Якщо збігів немає — так і напиши.\n"
        "6) 🎭 СОЦІАЛЬНА ІНЖЕНЕРІЯ: імперсонація авторитету, терміновість, «Fwd:»-легітимізація, тема/тіло.\n"
        "7) 🎯 MITRE ATT&CK: доречні техніки (напр. T1566.002 spearphishing link, T1566.001 attachment, "
        "T1656 impersonation) з 1-рядковим поясненням.\n"
        "8) ✅ РЕКОМЕНДАЦІЇ: 3–6 конкретних дій (заблокувати домен/IP, попередити отримувача, перевірити "
        "хто відкривав, YARA/пошук по інших скриньках, звіт CERT-UA за потреби).\n"
        "9) 📌 IOC (defanged, списком): домени, IP, URL, email-адреси, хеші вкладень.\n"
        "Якщо якихось даних бракує — чесно познач «недостатньо даних», не вигадуй."
    )
    body = json.dumps(build_chat_payload(
        model=model,
        messages=[{'role': 'system', 'content': system},
                  {'role': 'user', 'content': facts}],
        role='fast',
        temperature=0.1,
        max_tokens=int(os.getenv('DFIR_TOOLS_EML_MAX_TOKENS', '3200')),
        stream=False,
        reasoning_effort=None,
        extra={'chat_template_kwargs': {'enable_thinking': False}},
    )).encode('utf-8')
    try:
        req = urllib.request.Request(llm_url, data=body,
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=int(os.getenv('DFIR_TOOLS_EML_TIMEOUT', '360'))) as r:
            rj = json.loads(r.read().decode('utf-8', errors='ignore'))
        _m = (rj.get('choices') or [{}])[0].get('message', {}) or {}
        _c = (_m.get('content') or '').strip()
        if not _c:
            _c = (_m.get('reasoning_content') or '').strip()
        _c = re.sub(r'</?[a-zA-Z!][^>]*>', '', _c)  # strip echoed HTML tags (raw-tag render bug #9)
        # strip LaTeX artefacts gemma sometimes emits ($\rightarrow$, \(..\), $..$)
        _c = _c.replace(r'$\rightarrow$', '→').replace(r'\rightarrow', '→')
        _c = re.sub(r'\$\s*\\?([a-zA-Z]+)\s*\$', lambda m: {'to': '→', 'rightarrow': '→'}.get(m.group(1), m.group(1)), _c)
        _c = re.sub(r'\\[()\[\]]', '', _c)
        _c = re.sub(r'[ \t]{2,}', ' ', _c)
        return _c.strip()
    except Exception as e:                                  # noqa: BLE001
        if log:
            log.error("[addtools] eml llm analysis failed: %s", e)
        return None


def _do_email(chat_id, st):
    workdir = st['workdir']
    path = st['file_path']
    ext = os.path.splitext(st['orig_name'])[1].lower()
    try:
        if ext == '.msg':
            summary, attachments, meta, html_body, text_body = _parse_msg(path)
        else:
            summary, attachments, meta, html_body, text_body = _parse_eml(path)
        _send_plain(chat_id, summary[:3800])

        # 1) Safe standalone HTML preview (scripts/styles/remote resources off)
        ext_links = meta.get('links') or []
        try:
            html_bytes, ext_links, remote_imgs = _build_eml_preview_html(
                meta, html_body, text_body)
            base = os.path.splitext(st['orig_name'])[0] or 'email'
            cap = "\U0001f512 Безпечний HTML-перегляд листа (скрипти/трекери вимкнено)."
            if remote_imgs:
                cap += "\n⚠ Заблоковано %d віддалених зображень." % len(remote_imgs)
            _tg_send_document(chat_id, html_bytes, "%s_preview.html" % base,
                              caption=cap, content_type='text/html')
        except Exception as e:                              # noqa: BLE001
            ext_links = meta.get('links') or []
            if log:
                log.error("[addtools] eml preview failed: %s", e)

        # 2+3) Local-LLM analysis with a LIVE progress card (elapsed/%/GPU), then
        # attachments. Runs on a worker thread so the heartbeat animates during the
        # gemma-31b analysis instead of a static line. (empty-content bug fixed in
        # _eml_llm_analysis: gemma-4-31b + enable_thinking:false + reasoning salvage.)
        def _eml_work():
            analysis = _eml_llm_analysis(meta, text_body, ext_links, attachments)
            if analysis:
                # richer top-tier analysis can exceed one Telegram message -> chunk on
                # section boundaries so nothing gets truncated
                full = "🛡 LLM-аналіз листа:\n\n" + analysis
                if len(full) <= 3900:
                    _send_plain(chat_id, full)
                else:
                    buf = ''
                    for para in full.split('\n\n'):
                        if len(buf) + len(para) + 2 > 3800 and buf:
                            _send_plain(chat_id, buf.rstrip())
                            buf = ''
                        buf += para + '\n\n'
                    if buf.strip():
                        _send_plain(chat_id, buf.rstrip())
            else:
                _send_plain(chat_id, "ℹ️ LLM-аналіз недоступний (порожня відповідь).")
            for name, data in attachments[:10]:
                sha = hashlib.sha256(data).hexdigest()
                _tg_send_document(chat_id, data, name,
                                  caption=f"📎 {name}\nSHA256: {sha}")
        try:
            _run_with_progress(chat_id, 'eml_analysis', "🤖 Аналізую лист через локальну LLM", _eml_work)
        except Exception:
            _eml_work()
    except Exception as e:                                   # noqa: BLE001
        if log:
            log.error("[addtools] email parse failed: %s", e)
        _send_plain(chat_id, "❌ Не вдалося розібрати лист.")
    _cleanup(workdir)


def _decode_best(raw, declared=None):
    """Decode bytes to text robustly for UA/RU mail (utf-8 / windows-1251 / koi8-u
    / raw-8bit). Picks the candidate with the FEWEST U+FFFD replacements so a
    Cyrillic email that lies about (or omits) its charset still reads correctly."""
    if raw is None:
        return ''
    if isinstance(raw, str):
        return raw
    if not raw:
        return ''
    try:
        from charset_normalizer import from_bytes
        g = from_bytes(raw).best()
        if g is not None:
            s = str(g)
            if s.count('�') == 0:
                return s
    except Exception:
        pass
    cands = []
    if declared:
        cands.append(declared)
    cands += ['utf-8', 'windows-1251', 'cp1251', 'koi8-u', 'koi8-r', 'iso-8859-5', 'cp1252', 'latin-1']
    best, best_bad = None, 1 << 30
    for enc in cands:
        try:
            s = raw.decode(enc, errors='replace')
        except Exception:
            continue
        bad = s.count('�')
        if bad < best_bad:
            best, best_bad = s, bad
            if bad == 0:
                break
    return best if best is not None else raw.decode('utf-8', 'replace')


def _decode_header_best(val):
    """RFC2047 (=?charset?B/Q?…?=) + raw-8bit header decode with UA/RU fallback."""
    if not val:
        return ''
    try:
        from email.header import decode_header
        # compat32 hands a raw 8-bit header (From: Іван without RFC 2047) back as a Header object
        # with charset unknown-8bit; str() on it turned every byte into «�». decode_header() on
        # the object itself returns the original bytes, which go through the same charset
        # guessing as the body.
        from email.header import Header
        sval = val if isinstance(val, Header) else str(val)
        out = []
        for txt, enc in decode_header(sval):
            enc = None if enc == 'unknown-8bit' else enc
            out.append(_decode_best(txt, enc) if isinstance(txt, bytes) else txt)
        return ''.join(out)
    except Exception:
        return str(val)


def _parse_eml(path):
    import email
    with open(path, 'rb') as fh:
        # compat32 (default) keeps headers RAW so we control charset decoding
        msg = email.message_from_binary_file(fh)

    def _H(name):
        return _decode_header_best(msg.get(name, ''))

    received = ['  '.join(r.split())[:300] for r in (msg.get_all('Received', []) or [])]
    meta = {
        'from': _H('From'), 'to': _H('To'),
        'subject': _H('Subject'), 'date': msg.get('Date', ''),
        'message_id': msg.get('Message-ID', ''),
        'reply_to': _H('Reply-To'),
        'return_path': msg.get('Return-Path', ''),
        'auth_results': _H('Authentication-Results'),
        'received_spf': msg.get('Received-SPF', ''),
        'x_mailer': _H('X-Mailer') or _H('User-Agent'),
        'received': received,
    }
    lines = ["\U0001f4e7 EML — підсумок заголовків:",
             f"From:    {meta['from']}",
             f"To:      {meta['to']}",
             f"Subject: {meta['subject']}",
             f"Date:    {meta['date']}",
             f"Message-ID: {meta['message_id']}",
             f"Reply-To:   {meta['reply_to']}",
             f"Return-Path: {meta['return_path']}",
             f"Auth-Results: {meta['auth_results'][:300]}",
             "", f"Received-ланцюг ({len(received)}):"]
    for r in received[:8]:
        lines.append("  • " + r[:200])

    text_body, html_body = '', ''
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get_filename():
            continue
        ct = part.get_content_type()
        if ct == 'text/plain' and not text_body:
            text_body = _decode_best(part.get_payload(decode=True), part.get_content_charset())
        elif ct == 'text/html' and not html_body:
            html_body = _decode_best(part.get_payload(decode=True), part.get_content_charset())

    lines += ["", "Тіло (фрагмент):", (text_body or '(HTML-only — див. preview)')[:1500]]
    attachments = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            try:
                fn = _decode_header_best(fn)
            except Exception:
                pass
            attachments.append((fn, part.get_payload(decode=True) or b''))
    meta['links'] = re.findall(r'https?://[^\s"\'<>)]+', html_body or text_body or '')[:40]
    return '\n'.join(lines), attachments, meta, html_body, text_body

def _parse_msg(path):
    try:
        import extract_msg
    except Exception:
        return ("❌ Підтримка .msg недоступна (extract-msg не встановлено). "
                "Конвертуйте у .eml.", [], {}, '', '')
    m = extract_msg.Message(path)
    text_body = m.body or ''
    html_body = ''
    try:
        hb = getattr(m, 'htmlBody', None)
        if isinstance(hb, bytes):
            html_body = hb.decode('utf-8', 'replace')
        elif isinstance(hb, str):
            html_body = hb
    except Exception:
        html_body = ''
    meta = {
        'from': m.sender, 'to': m.to, 'subject': m.subject, 'date': str(m.date),
        'message_id': getattr(m, 'messageId', ''), 'reply_to': '',
        'return_path': '', 'auth_results': getattr(m, 'headerDict', {}) and
        m.headerDict.get('Authentication-Results', '') or '',
        'received_spf': '', 'x_mailer': '', 'received': [],
    }
    lines = ["\U0001f4e7 MSG — підсумок:",
             f"From:    {m.sender}",
             f"To:      {m.to}",
             f"Subject: {m.subject}",
             f"Date:    {m.date}",
             f"Message-ID: {getattr(m, 'messageId', '')}",
             "", "Тіло (фрагмент):", text_body[:1500]]
    attachments = []
    for att in (m.attachments or []):
        name = att.longFilename or att.shortFilename or 'attachment.bin'
        attachments.append((name, att.data or b''))
    m.close()
    meta['links'] = re.findall(r'https?://[^\s"\'<>)]+', html_body or text_body or '')[:40]
    return '\n'.join(lines), attachments, meta, html_body, text_body



# --- Hex / strings viewer ----------------------------------------------------
def _do_hexview(chat_id, st):
    workdir = st['workdir']
    with open(st['file_path'], 'rb') as fh:
        data = fh.read(HEXVIEW_CAP)
    # hexdump
    dump_lines = []
    for off in range(0, min(len(data), 1024), 16):  # show first 1 KB in chat
        chunk = data[off:off + 16]
        hexpart = ' '.join(f'{b:02x}' for b in chunk).ljust(47)
        asci = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        dump_lines.append(f'{off:08x}  {hexpart}  {asci}')
    # printable strings (ASCII >=4 and UTF-16LE)
    ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', data)
    utf16 = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data)
    strings = [s.decode('ascii', 'replace') for s in ascii_strings[:40]]
    strings += [s.decode('utf-16-le', 'replace') for s in utf16[:20]]
    msg = ("#️⃣ Hexdump (перші 1 КБ):\n" + '\n'.join(dump_lines) +
           "\n\nStrings (фрагмент):\n" + '\n'.join(strings[:50]))
    _send_plain(chat_id, msg[:3900])
    _cleanup(workdir)


def _clear_pending_from_state(chat_id, st):
    """Text tools store no workdir; just clear pending for this chat/user."""
    PENDING.pop((str(chat_id), str(st.get('user_id'))), None)


# =============================================================================
#  Dispatch tables
# =============================================================================
#  File-stage handlers: invoked after the file is downloaded (and any extra
#  param collected). Native ones proxy to the sidecar.
def _do_transcribe(chat_id, st):
    """Audio/video -> text via the host GPU Whisper large-v3 service. Any container/
    codec (PyAV decodes). Auto language (UK/RU/mix friendly). Runs under the live
    progress card; transcript pushed back (chunked if long)."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'audio', fh.read())}
            with httpx.Client(timeout=900) as client:
                resp = client.post(f'{WHISPER_URL}/asr', files=files,
                                   data={'language': st.get('language', 'auto'), 'task': 'transcribe'})
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс транскрипції недоступний. Спробуйте пізніше.")
                return
            d = resp.json()
            txt = (d.get('text') or '').strip()
            lang = d.get('language', '?')
            dur = int(d.get('duration') or 0)
            langname = {'uk': 'українська', 'ru': 'російська', 'en': 'англійська',
                        'pl': 'польська', 'be': 'білоруська'}.get(lang, lang)
            if not txt:
                _send_plain(chat_id, "ℹ️ Мовлення не розпізнано (тиша / лише шум?). "
                                     "Спробуйте інший файл або гучніший фрагмент.")
                return
            header = f"🎤 Транскрипція (мова: {langname}, тривалість ~{dur} с):\n\n"
            full = header + txt
            CH = 3800
            if len(full) <= CH:
                _send_plain(chat_id, full)
            else:
                _send_plain(chat_id, header + "(довгий запис, надсилаю частинами)")
                for i in range(0, len(txt), CH):
                    _send_plain(chat_id, txt[i:i + CH])
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Транскрипція не вдалась: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'transcribe', '🎤 Транскрибую (Whisper large-v3, GPU)', _work)


def _do_img_enhance(chat_id, st):
    """Photo -> 4x super-resolution via the host Real-ESRGAN service. FORENSIC:
    AI upscale is a LEAD aid, not evidence (can hallucinate detail) — original kept,
    result carries a burned-in banner + we surface the input SHA-256."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'image', fh.read())}
            with httpx.Client(timeout=600) as client:
                resp = client.post(f'{IMG_ENHANCE_URL}/enhance', files=files)
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс покращення недоступний. Спробуйте пізніше.")
                return
            in_sha = resp.headers.get('X-Input-SHA256', '')
            plate_read = (resp.headers.get('X-Plate-Read', '') or '').strip()
            if plate_read:
                _read_line = "\n\n🔢 Розпізнані варіанти (авто-здогад, ЗВІРТЕ з фото): " + plate_read
            else:
                _read_line = ("\n\n🔢 Автоматично зчитати не вдалось (далеко/розмито/стиснуто).\n"
                             "🚗 ДЛЯ НОМЕРНОГО ЗНАКА краще натисніть «Номер/розмите фото (деблюр)» — вона відновлює різкість саме для номерів і НЕ домислює символи (×4 апскейл може вигадати цифри).\n"
                             "Порада: надсилайте фото ФАЙЛОМ (не стиснене) або зніміть ближче/чіткіше.")
            cap = ("🖼 Покращено (Real-ESRGAN ×4)\n"
                   "⚠️ AI-апскейл — для ЗАЧІПКИ, НЕ доказ (можливе домислення деталей). "
                   "Оригінал не змінено.\n"
                   "SHA-256 вхідного: " + (in_sha[:48] or '—') + _read_line)
            _tg_send_document(chat_id, resp.content,
                              (os.path.splitext(st['orig_name'])[0] or 'image') + '_enhanced.png',
                              caption=cap, content_type='image/png')
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Покращення не вдалось: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'img_enhance', '🖼 Покращую фото (Real-ESRGAN ×4)', _work)


def _do_img_plate(chat_id, st):
    """Blurry/out-of-focus plate photo -> forensic CONTACT SHEET of deblur+SR variants
    (Wiener deconvolution motion/defocus + CLAHE + unsharp + Real-ESRGAN SR) via the host
    image service /plate. FORENSIC: deterministic deconvolution dominates (no fabricated
    chars); GAN SR is one labelled option; original kept, banner + input SHA-256."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'image', fh.read())}
            with httpx.Client(timeout=600) as client:
                resp = client.post(f'{IMG_ENHANCE_URL}/plate', files=files)
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс покращення недоступний. Спробуйте пізніше.")
                return
            in_sha = resp.headers.get('X-Input-SHA256', '')
            cap = ("🚗 Контактний лист варіантів (деблюр + контраст + SR)\n"
                   "Оберіть найчіткіший для зчитування знака. Деконволюція — детермінована "
                   "(без домислювання символів); Super-Res ×4 — окремий AI-варіант.\n"
                   "⚠️ Для ЗАЧІПКИ, НЕ доказ. Оригінал не змінено.\n"
                   "SHA-256 вхідного: " + (in_sha[:48] or '—'))
            _tg_send_document(chat_id, resp.content,
                              (os.path.splitext(st['orig_name'])[0] or 'image') + '_plate_variants.png',
                              caption=cap, content_type='image/png')
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Покращення не вдалось: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'img_plate', '🚗 Обробляю номер (деблюр + SR)', _work)


def _do_diarize(chat_id, st):
    """Diarized transcription for operatives: WHO speaks + WHEN + trigger-word
    highlight. POSTs audio to the host whisper+ecapa service."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'audio', fh.read())}
            with httpx.Client(timeout=1800) as client:
                resp = client.post(f'{DIARIZE_URL}/diarize', files=files, data={'language': 'auto', 'num_speakers': st.get('num_speakers', '')})
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс діаризації недоступний. Спробуйте пізніше.")
                return
            d = resp.json()
            segs = d.get('segments') or []
            if not segs:
                _send_plain(chat_id, "ℹ️ Мовлення не розпізнано (тиша / лише шум?).")
                return
            ns = d.get('num_speakers', 0)
            lang = {'uk': 'українська', 'ru': 'російська', 'en': 'англійська'}.get(d.get('language'), d.get('language', '?'))
            dur = int(d.get('duration') or 0)
            found = set()
            body = []
            for o in segs:
                ss = int(o.get('start') or 0)
                line = "[%s %02d:%02d] %s" % (o.get('speaker', 'Спікер ?'), ss // 60, ss % 60, o.get('text', ''))
                hl, f = _highlight_triggers(line)
                found |= f
                body.append(hl)
            header = "🎙 Розмова — спікерів: %d · мова: %s · ~%d с\n" % (ns, lang, dur)
            if found:
                header += "🚨 ВИЯВЛЕНО ТРИГЕРИ: " + ", ".join(sorted(found)) + "\n"
            header += "─" * 22 + "\n"
            full = header + "\n".join(body)
            CH = 3800
            if len(full) <= CH:
                _send_plain(chat_id, full)
            else:
                _send_plain(chat_id, header + "(довга розмова — надсилаю частинами)")
                txt = "\n".join(body)
                for i in range(0, len(txt), CH):
                    _send_plain(chat_id, txt[i:i + CH])
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Діаризація не вдалась: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'diarize', '🎙 Розпізнаю розмову (хто говорить + тригери)', _work)


def _do_restore_faces(chat_id, st):
    """CodeFormer face restoration via the host image service (/restore_faces)."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'image', fh.read())}
            with httpx.Client(timeout=900) as client:
                resp = client.post(f'{IMG_ENHANCE_URL}/restore_faces', files=files)
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс відновлення облич недоступний. Спробуйте пізніше.")
                return
            in_sha = resp.headers.get('X-Input-SHA256', '')
            cap = ("🙂 Обличчя відновлено (CodeFormer)\n"
                   "⚠️ AI-відновлення — для ЗАЧІПКИ, НЕ доказ. Оригінал не змінено.\n"
                   "SHA-256 вхідного: " + (in_sha[:48] or '—'))
            _tg_send_document(chat_id, resp.content,
                              (os.path.splitext(st['orig_name'])[0] or 'image') + '_faces.png',
                              caption=cap, content_type='image/png')
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Відновлення облич не вдалось: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'restore_faces', '🙂 Відновлюю обличчя (CodeFormer)', _work)


def _do_audio_clean(chat_id, st):
    """Diagnose + clean a low-quality recording (denoise/AGC/normalize) and return
    BOTH a clear audio track AND the transcript. Proxies to the host Whisper /enhance.
    Built for the universal 'bad recording -> usable evidence' case."""
    workdir = st['workdir']
    def _work():
        try:
            with open(st['file_path'], 'rb') as fh:
                files = {'file': (os.path.basename(st['file_path']) or 'audio', fh.read())}
            with httpx.Client(timeout=1200) as client:
                resp = client.post(f'{WHISPER_URL}/enhance', files=files,
                                   data={'language': st.get('language', 'auto'), 'task': 'transcribe'})
            if resp.status_code != 200:
                _send_plain(chat_id, "❌ Сервіс обробки звуку недоступний. Спробуйте пізніше.")
                return
            d = resp.json()
            enh = d.get('enhanced', {}) or {}
            txt = (d.get('text') or '').strip()
            b64 = d.get('audio_b64') or ''
            fmt = (d.get('audio_fmt') or 'wav').lower()
            srt = d.get('srt') or ''
            base = os.path.splitext(st['orig_name'])[0] or 'audio'
            # 1) cleaned audio track (mp3 if encoder available, else wav)
            if b64:
                import base64 as _b64
                try:
                    ab = _b64.b64decode(b64)
                    _ct = 'audio/mpeg' if fmt == 'mp3' else 'audio/wav'
                    _tg_send_document(chat_id, ab, base + '_clean.' + fmt,
                                      caption="🔊 Очищений звук (денойз + підсилення голосу)",
                                      content_type=_ct)
                except Exception as _e:
                    _send_plain(chat_id, "⚠️ Очищене аудіо не надіслалось: " + str(_e)[:80])
            # 2) diagnostic summary
            try:
                _sil = int(float(enh.get('silence_ratio', 0)) * 100)
            except Exception:
                _sil = 0
            _send_plain(chat_id,
                "🧪 Діагностика звуку:\n"
                f"• тривалість ~{enh.get('dur_s','?')} с\n"
                f"• вхідний рівень {enh.get('rms_in_dbfs','?')} dBFS · шум {enh.get('noise_floor_dbfs','?')} dBFS · SNR {enh.get('snr_db','?')} дБ · тиша {_sil}%\n"
                f"• обробка: денойз {enh.get('denoise','?')} · підсилення ×{enh.get('makeup_gain_x','?')} → вихід {enh.get('rms_out_dbfs','?')} dBFS")
            # 3) transcript
            if not txt:
                _send_plain(chat_id, "ℹ️ Голос не розпізнано навіть після очищення — у записі, ймовірно, немає розбірливого мовлення.")
                return
            lang = d.get('language', '?')
            langname = {'uk': 'українська', 'ru': 'російська', 'en': 'англійська',
                        'pl': 'польська', 'be': 'білоруська'}.get(lang, lang)
            header = f"🎤 Транскрипт (мова: {langname}):\n\n"
            CH = 3800
            if len(header + txt) <= CH:
                _send_plain(chat_id, header + txt)
            else:
                _send_plain(chat_id, header + "(довгий запис, надсилаю частинами)")
                for i in range(0, len(txt), CH):
                    _send_plain(chat_id, txt[i:i + CH])
            # 4) SRT subtitles with timecodes (separate file)
            if srt.strip():
                try:
                    _tg_send_document(chat_id, srt.encode('utf-8'), base + '.srt',
                                      caption="🕒 Субтитри з таймкодами (SRT)",
                                      content_type='application/x-subrip')
                except Exception:
                    pass
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Обробка звуку не вдалась: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'audio_clean', '🔊 Чищу і транскрибую звук (денойз+AGC+Whisper)', _work)


def _do_book_mp3(chat_id, st):
    """EPUB/PDF/FB2/DOCX/TXT book -> UA-voice MP3 audiobook. Proxies the sidecar
    /book-to-mp3 (text extraction + Piper TTS, segment-by-segment, memory-bounded);
    delivery mirrors audio_translate_ua: inline document when small, link otherwise."""
    workdir = st['workdir']
    import uuid as _uuid_bk
    _prog_key = 'prog_' + _uuid_bk.uuid4().hex + '.prog'
    _prog_path = os.path.join(os.getenv('DFIR_AUDIO_RESULTS_DIR', '/audio_results'), _prog_key)

    def _work():
        try:
            resp = _sidecar_post('/book-to-mp3', st['file_path'],
                                 {'progress_file': _prog_key},
                                 timeout=AUDIO_SIDECAR_TIMEOUT)
            if resp.status_code != 200:
                _send_plain(chat_id, _sidecar_err_message(resp))
                return
            d = resp.json()
            b64 = d.get('audio_b64') or ''
            result_url = (d.get('result_url') or '').strip()
            text_url = (d.get('text_url') or '').strip()
            dur = int(d.get('dur_s') or 0)
            try:
                size_bytes = int(d.get('size_bytes') or 0)
            except Exception:
                size_bytes = 0
            size_mb = size_bytes / (1024.0 * 1024.0) if size_bytes else 0.0
            base = os.path.splitext(st['orig_name'])[0] or 'book'
            _h, _m = dur // 3600, (dur % 3600) // 60
            _durtxt = ('%d год %d хв' % (_h, _m)) if _h else ('%d хв' % max(_m, 1))
            cap = '📖→🔊 Аудіокнига готова (~%s звучання)' % _durtxt
            if d.get('truncated'):
                cap += '\n⚠️ Книга дуже велика — озвучено першу частину.'
            if b64 and 0 < size_bytes <= AUDIO_TG_LIMIT:
                try:
                    import base64 as _b64mod
                    ab = _b64mod.b64decode(b64)
                    _tg_send_document(chat_id, ab, base + '_audiobook.mp3',
                                      caption=cap, content_type='audio/mpeg')
                    if result_url:
                        _send_plain(chat_id, "⬇️ Резервне посилання (VPN, %d днів):\n%s"
                                    % (AUDIO_RESULTS_KEEP_DAYS, result_url))
                except Exception:
                    if result_url:
                        _send_plain(chat_id, cap + "\n\n⬇️ Посилання (VPN, %d днів):\n%s"
                                    % (AUDIO_RESULTS_KEEP_DAYS, result_url))
            elif result_url:
                _send_plain(chat_id, cap + " — %.0f МБ, завеликий файл для Telegram.\n\n"
                            "⬇️ Посилання для завантаження (VPN, зберігається %d днів):\n%s"
                            % (size_mb, AUDIO_RESULTS_KEEP_DAYS, result_url))
            else:
                _send_plain(chat_id, "⚠️ Озвучка не повернулась. Повідомте адміністратора.")
                return
            if text_url:
                _send_plain(chat_id, "📄 Витягнутий текст книги (txt):\n" + text_url)
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Аудіокнига не вдалася: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'book_mp3',
                       '📖→🔊 Витягую текст → озвучую українським голосом (Piper)', _work,
                       progress_path=_prog_path)


def _do_audio_translate_ua(chat_id, st):
    """EN audio -> UK spoken MP3. Proxies to the sidecar /audio-translate-ua, which
    chains host Whisper (EN transcript) -> translate-9b (UK text) -> Piper TTS -> MP3.
    Returns the UK-voice MP3 + the UK translation text (+ the source EN transcript)."""
    workdir = st['workdir']
    import uuid as _uuid_atr
    _prog_key = 'prog_' + _uuid_atr.uuid4().hex + '.prog'
    _prog_path = os.path.join(os.getenv('DFIR_AUDIO_RESULTS_DIR', '/audio_results'), _prog_key)
    def _work():
        try:
            resp = _sidecar_post('/audio-translate-ua', st['file_path'],
                                 {'language': st.get('language', 'en'), 'progress_file': _prog_key},
                                 timeout=AUDIO_SIDECAR_TIMEOUT)
            if resp.status_code != 200:
                _send_plain(chat_id, _sidecar_err_message(resp))
                return
            d = resp.json()
            en_text = (d.get('en_text') or '').strip()
            ua_text = (d.get('ua_text') or '').strip()
            b64 = d.get('audio_b64') or ''
            fmt = (d.get('audio_fmt') or 'mp3').lower()
            dur = int(d.get('dur_s') or 0)
            base = os.path.splitext(st['orig_name'])[0] or 'audio'
            # NEW (2026-07-05): the sidecar now processes long lectures in a
            # memory-bounded, segment-by-segment way and writes the final MP3
            # DIRECTLY into the shared results dir, returning `result_url`. When
            # present we deliver by link and SKIP the base64 decode + re-save
            # entirely (no OOM, no giant bytes object crossing the wire).
            result_url = (d.get('result_url') or '').strip()
            ua_text_url = (d.get('ua_text_url') or '').strip()
            en_text_url = (d.get('en_text_url') or '').strip()
            try:
                size_bytes = int(d.get('size_bytes') or 0)
            except Exception:
                size_bytes = 0
            size_mb = size_bytes / (1024.0 * 1024.0) if size_bytes else 0.0
            # 1) UK-voice MP3 delivery
            if result_url:
                # Memory-bounded path. Small enough for Telegram AND we still have
                # the inline bytes -> send the document + link fallback; otherwise
                # link only (Telegram sendDocument hard-caps bot uploads at 50 MB).
                if b64 and 0 < size_bytes <= AUDIO_TG_LIMIT:
                    try:
                        import base64 as _b64
                        ab = _b64.b64decode(b64)
                        _tg_send_document(chat_id, ab, base + '_ua.' + fmt,
                                          caption="🇺🇦 Українська озвучка (переклад з англійської)",
                                          content_type='audio/mpeg' if fmt == 'mp3' else 'audio/wav')
                        _send_plain(chat_id,
                                    "⬇️ Резервне посилання на файл (VPN, %d днів):\n%s"
                                    % (AUDIO_RESULTS_KEEP_DAYS, result_url))
                    except Exception as _e:
                        _send_plain(chat_id,
                                    "🇺🇦 Українська озвучка готова.\n\n⬇️ Посилання (VPN, %d днів):\n%s"
                                    % (AUDIO_RESULTS_KEEP_DAYS, result_url))
                else:
                    if log:
                        log.info('[addtools] audiotr result %.1f MB -> link-only delivery %s', size_mb, result_url)
                    _send_plain(chat_id,
                                "🇺🇦 Українська озвучка готова (%.0f МБ — завеликий файл для Telegram).\n\n"
                                "⬇️ Посилання для завантаження (працює через VPN, "
                                "зберігається %d днів):\n%s" % (size_mb, AUDIO_RESULTS_KEEP_DAYS, result_url))
            elif b64:
                # LEGACY small-file path (sidecar returned only base64, no link).
                import base64 as _b64
                try:
                    ab = _b64.b64decode(b64)
                    link, _rn = _audio_results_save(ab, base, fmt)
                    size_mb = len(ab) / (1024.0 * 1024.0)
                    if len(ab) > AUDIO_TG_LIMIT:
                        if log:
                            log.info('[addtools] audiotr result %.1f MB > TG limit -> link-only delivery', size_mb)
                        if link:
                            _send_plain(chat_id,
                                        "🇺🇦 Українська озвучка готова (%.0f МБ — завеликий файл для Telegram).\n\n"
                                        "⬇️ Посилання для завантаження (працює через VPN, "
                                        "зберігається %d днів):\n%s" % (size_mb, AUDIO_RESULTS_KEEP_DAYS, link))
                        else:
                            _send_plain(chat_id,
                                        "⚠️ Озвучка готова (%.0f МБ), але завелика для Telegram і не "
                                        "вдалося зберегти її для завантаження. Повідомте адміністратора." % size_mb)
                    else:
                        _tg_send_document(chat_id, ab, base + '_ua.' + fmt,
                                          caption="🇺🇦 Українська озвучка (переклад з англійської)",
                                          content_type='audio/mpeg' if fmt == 'mp3' else 'audio/wav')
                        if link:
                            _send_plain(chat_id,
                                        "⬇️ Резервне посилання на файл (VPN, %d днів):\n%s"
                                        % (AUDIO_RESULTS_KEEP_DAYS, link))
                except Exception as _e:
                    _send_plain(chat_id, "⚠️ Аудіо не надіслалось: " + str(_e)[:80])
            # 2) UK translation text — link if the sidecar stashed a huge .txt,
            #    else inline (chunked to Telegram's message limit).
            CH = 3800
            if ua_text_url:
                _send_plain(chat_id,
                            "🇺🇦 Переклад українською (тривалість оригіналу ~%d с) — довгий текст, "
                            "повний файл:\n%s\n\nПерші фрагменти:" % (dur, ua_text_url))
                _send_plain(chat_id, ua_text[:CH])
            elif ua_text:
                header = f"🇺🇦 Переклад українською (тривалість оригіналу ~{dur} с):\n\n"
                if len(header + ua_text) <= CH:
                    _send_plain(chat_id, header + ua_text)
                else:
                    _send_plain(chat_id, header + "(довгий текст, надсилаю частинами)")
                    for i in range(0, len(ua_text), CH):
                        _send_plain(chat_id, ua_text[i:i + CH])
            # 3) source EN transcript (reference)
            if en_text_url:
                _send_plain(chat_id, "🇬🇧 Оригінал (англійська) — повний файл:\n" + en_text_url)
            elif en_text:
                eh = "🇬🇧 Оригінал (англійська, розпізнано):\n\n"
                if len(eh + en_text) <= CH:
                    _send_plain(chat_id, eh + en_text)
                else:
                    for i in range(0, len(en_text), CH):
                        _send_plain(chat_id, (eh if i == 0 else '') + en_text[i:i + CH])
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Переклад аудіо не вдався: " + str(e)[:140])
        finally:
            _cleanup(workdir)
    _run_with_progress(chat_id, 'audio_translate_ua',
                       '🌐→🇺🇦 Розпізнаю → перекладаю → озвучую (Whisper+ШІ+Piper)', _work, progress_path=_prog_path)


def _do_bookidx_index(chat_id, st):
    """Study offline exam index. Runs immediately; only asks for a password if
    the PDF turns out to be encrypted (sidecar returns bad_password)."""
    workdir = st['workdir']
    def _work():
        fields = {'password': st.get('password', ''),
                  'book_label': st.get('book_label') or (os.path.splitext(st.get('orig_name', 'Book 1'))[0] or 'Book 1'),
                  'page_offset': str(st.get('page_offset', 0))}
        resp = _sidecar_post('/bookidx/index', st['file_path'], fields)
        _bookidx_index_finish(chat_id, st, resp, workdir)
    _run_with_progress(chat_id, 'bookidx_index', '📚 Book-індекс (offline, локальна ШІ)', _work)


def _bookidx_index_finish(chat_id, st, resp, workdir):
    if resp.status_code == 200:
        entries = resp.headers.get('X-Bookidx-Entries', '?')
        flagged = resp.headers.get('X-Bookidx-Flagged', '?')
        _tg_send_document(chat_id, resp.content,
                          (os.path.splitext(st['orig_name'])[0] or 'bookidx') + '_index.zip',
                          caption=("\U0001F4DA Book-індекс готовий: %s записів (на перевірку: %s).\n"
                                   "Всередині: index.xlsx/csv, commands_cheatsheet.csv, index.docx, "
                                   "index_review.csv, run_report.txt." % (entries, flagged)),
                          content_type='application/zip')
        _cleanup(workdir)
    elif resp.status_code == 422:
        # encrypted PDF -> keep the file, ask the user for the password
        _set_pending(chat_id, st.get('user_id'), 'bookidx_index', 'await_pw',
                     file_path=st['file_path'], orig_name=st['orig_name'], workdir=workdir)
        _send_plain(chat_id, "\U0001F511 PDF запаролений. Введіть пароль (наступним повідомленням):")
    else:
        _send_plain(chat_id, _sidecar_err_message(resp))
        _cleanup(workdir)


def _do_ioc_add(chat_id, st):
    """Manual IOC add (pasted text). Hands the text to the case-maintainer
    /ioc-manual/preview endpoint, which resolves the active case, extracts candidate
    indicators (regex + LLM, no storing) and sends a grouped approval card back to
    Telegram. Backgrounded so the /addtools/message request thread returns at once."""
    text = st.get('text') or ''

    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/ioc-manual/preview',
                             data=json.dumps({'chat_id': chat_id, 'text': text}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=240).read()
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, '❌ Не вдалося проаналізувати текст: ' + str(e)[:150])

    _send_plain(chat_id, '🔎 Аналізую текст, шукаю індикатори…')
    threading.Thread(target=_work, daemon=True).start()


def _do_misp_export(chat_id):
    """Export the ACTIVE case's IOCs as a MISP-importable JSON bundle (for CERT-UA / MISP).
    Delegates to /ioc-export/misp, which resolves the active case and sends the .json document."""
    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/ioc-export/misp',
                             data=json.dumps({'chat_id': chat_id}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=60).read()
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, '❌ Не вдалося сформувати MISP-бандл: ' + str(e)[:150])

    _send_plain(chat_id, '🛡 Формую MISP-бандл IOC активного кейсу…')
    threading.Thread(target=_work, daemon=True).start()


def _do_misp_export_all(chat_id):
    """ADMIN-ONLY: export IOCs from ALL cases as one MISP bundle (master indicator
    set for CERT-UA + future cross-case matching). Delegates to /ioc-export/misp-all."""
    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/ioc-export/misp-all',
                             data=json.dumps({'chat_id': chat_id}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=90).read()
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, '❌ Не вдалося сформувати MISP-бандл: ' + str(e)[:150])
    _send_plain(chat_id, '🛡 Формую MISP-бандл IOC ПО ВСІХ КЕЙСАХ…')
    threading.Thread(target=_work, daemon=True).start()


def _do_file_analysis(chat_id, st):
    """One-shot file triage in ONE button: metadata + YARA virus scan + static
    malware analysis (strings/PE/entropy). STATIC only — the file is never
    executed. The workdir is wiped right after (see _cleanup)."""
    fp = st['file_path']
    parts = ['\U0001F52C АНАЛІЗ ФАЙЛУ: %s' % st.get('orig_name', '?')]
    try:
        rm = _sidecar_post('/meta', fp)
        if rm.status_code == 200:
            dm = rm.json()
            parts.append('SHA256: %s' % (dm.get('sha256', '') or '')[:40])
            rep = dm.get('report'); meta = dm.get('meta') or {}
            if rep:
                parts.append('\n\U0001F4CB Метадані:\n' + str(rep)[:1100])
            elif meta:
                parts.append('\n\U0001F4CB Метадані (%s):' % dm.get('kind'))
                for k, v in list(meta.items())[:14]:
                    if v not in (None, '', {}):
                        parts.append('• %s: %s' % (k, str(v)[:110]))
    except Exception:
        pass
    try:
        ry = _sidecar_post('/yara', fp)
        if ry.status_code == 200:
            matches = (ry.json() or {}).get('matches', [])
            if matches:
                parts.append('\n\U0001F9EC YARA — \U0001F534 ЗНАЙДЕНО %d:' % len(matches))
                for m in matches[:8]:
                    parts.append('\U0001F534 %s [%s] %s' % (m.get('rule', ''), m.get('severity', ''), m.get('mitre', '')))
            else:
                parts.append('\n\U0001F9EC YARA: чисто (жодне правило не спрацювало)')
    except Exception:
        pass
    try:
        rs = _sidecar_post('/malware-static', fp)
        if rs.status_code == 200:
            ds = rs.json()
            parts.append('\n\U0001F50E Статичний аналіз: тип %s · ентропія %s%s · вирок: %s' % (
                ds.get('type'), ds.get('entropy'),
                ' (ймовірно упакований)' if ds.get('packed_likely') else '', ds.get('verdict')))
            io = ds.get('iocs', {}) or {}
            if io.get('suspicious_apis'):
                parts.append('⚠ Небезпечні API: ' + ', '.join(io['suspicious_apis'][:10]))
            if io.get('urls'):
                parts.append('\U0001F310 URL: ' + ', '.join(io['urls'][:6]))
            if io.get('ips'):
                parts.append('\U0001F4E1 IP: ' + ', '.join(io['ips'][:6]))
            pe = ds.get('pe') or {}
            if pe and not pe.get('error'):
                parts.append('\U0001F9E9 PE: компіляція %s · %s%s' % (
                    pe.get('compile_time'), 'DLL' if pe.get('is_dll') else 'EXE',
                    (' · небезпечні імпорти: ' + ', '.join(pe.get('imported_dangerous', [])[:8]))
                    if pe.get('imported_dangerous') else ''))
    except Exception:
        pass
    parts.append('\n_(статичний аналіз, файл НЕ запускався; не є доказом)_')
    _send_plain(chat_id, '\n'.join(parts)[:3900])
    try:
        _cleanup(st['workdir'])
    except Exception:
        pass


FILE_DISPATCH = {
    'pdf_translate': _do_pdf_translate,
    'transcribe':    _do_transcribe,
    'audio_clean':   _do_audio_clean,
    'audio_translate_ua': _do_audio_translate_ua,
    'book_mp3': _do_book_mp3,
    'img_enhance':   _do_img_enhance,
    'img_plate':     _do_img_plate,
    'diarize':       _do_diarize,
    'restore_faces': _do_restore_faces,
    'bookidx_index':    _do_bookidx_index,
    'pdf_unlock':    _do_pdf_unlock,
    'pdf_watermark': _do_pdf_watermark,
    'ocr':           _do_ocr,
    'meta':          _do_meta,
    'yara':          _do_yara,
    'fileanalysis':  _do_file_analysis,
    'translate':     _do_translate,
    'hash':          _do_hash,
    'email':         _do_email,
    'hexview':       _do_hexview,
}
#  Text-stage handlers (pure-python, no file).
TEXT_DISPATCH = {
    'defang':     _do_defang,
    'decode':     _do_decode,
    'iocextract': _do_iocextract,
    'ioc_add':    _do_ioc_add,
}


# =============================================================================
#  Update handlers — called by the Flask endpoints (n8n routes Telegram to them)
# =============================================================================
def handle_open_menu(chat_id):
    """Show the Additional Tools submenu."""
    _send_plain(chat_id, TOOLS_MENU_TITLE, reply_markup=_menu_keyboard(chat_id))


HELP_MD = (
    "\U0001F6E1 *DFIR-\u0431\u043e\u0442 \u2014 \u043f\u043e\u0432\u043d\u0430 \u0434\u043e\u0432\u0456\u0434\u043a\u0430*\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *1. \U0001F4E5 \u0417\u0411\u0406\u0420 \u041b\u041e\u0413\u0406\u0412 (\u043a\u043e\u043b\u0435\u043a\u0442\u043e\u0440)* \u2501\u2501\u2501\u2501\u2501\n"
    "\u041a\u043e\u043b\u0435\u043a\u0442\u043e\u0440 \u0437\u0431\u0438\u0440\u0430\u0454 \u0430\u0440\u0442\u0435\u0444\u0430\u043a\u0442\u0438 KAPE + \u043f\u0456\u0434\u043e\u0437\u0440\u0456\u043b\u0456 \u0431\u0456\u043d\u0430\u0440\u043d\u0438\u043a\u0438.\n"
    "1\uFE0F\u20E3 \u0417\u0430\u0432\u0430\u043d\u0442\u0430\u0436: http://CHANGE_ME_DFIR_LINK_IP:8080/collector.exe\n"
    "   (\u0430\u0431\u043e \u043a\u043d\u043e\u043f\u043a\u0430 \u00ab\U0001F4E5 \u0417\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0438\u0442\u0438 \u043a\u043e\u043b\u0435\u043a\u0442\u043e\u0440\u00bb \u043d\u0438\u0436\u0447\u0435)\n"
    "2\uFE0F\u20E3 \u041f\u0440\u0430\u0432\u0430 \u043a\u043d\u043e\u043f\u043a\u0430 \u2192 *\u0417\u0430\u043f\u0443\u0441\u043a \u0432\u0456\u0434 \u0456\u043c\u0435\u043d\u0456 \u0430\u0434\u043c\u0456\u043d\u0456\u0441\u0442\u0440\u0430\u0442\u043e\u0440\u0430* (SmartScreen \u2192 \u00ab\u0414\u0435\u0442\u0430\u043b\u044c\u043d\u0456\u0448\u0435\u00bb \u2192 \u00ab\u0412\u0438\u043a\u043e\u043d\u0430\u0442\u0438 \u0432\u0441\u0435 \u043e\u0434\u043d\u043e\u00bb)\n"
    "3\uFE0F\u20E3 \u0412\u0456\u0434\u043f\u043e\u0432\u0456\u0434\u0430\u0439 \u043d\u0430 \u043f\u0438\u0442\u0430\u043d\u043d\u044f (\u0441\u0446\u0435\u043d\u0430\u0440\u0456\u0439 / \u0434\u0438\u0441\u043a / \u043d\u0430\u0437\u0432\u0430 \u0441\u043f\u0440\u0430\u0432\u0438 / \u0433\u043b\u0438\u0431\u0438\u043d\u0430)\n"
    "4\uFE0F\u20E3 \u0414\u043e\u0447\u0435\u043a\u0430\u0439\u0441\u044f `DONE` \u2192 \u043e\u0442\u0440\u0438\u043c\u0430\u0454\u0448 ZIP \u0441\u043f\u0440\u0430\u0432\u0438\n"
    "5\uFE0F\u20E3 \u0417\u0430\u043b\u0438\u0439 ZIP \u0441\u044e\u0434\u0438 \u0432 \u0431\u043e\u0442\n"
    "\u26A0\uFE0F \u041a\u043e\u043b\u0435\u043a\u0442\u043e\u0440 \u043d\u0456\u0447\u043e\u0433\u043e \u043d\u0456\u043a\u0443\u0434\u0438 \u043d\u0435 \u0448\u043b\u0435 \u2014 \u043b\u0438\u0448\u0435 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u0438\u0439 ZIP.\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *2. \U0001F4CA \u0410\u041d\u0410\u041b\u0406\u0417 \u041a\u0415\u0419\u0421\u0423* \u2501\u2501\u2501\u2501\u2501\n"
    "\u041d\u0430\u0434\u0456\u0448\u043b\u0438 ZIP \u0441\u043f\u0440\u0430\u0432\u0438 \u2014 \u0431\u043e\u0442 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u043d\u043e:\n"
    "\u2022 \u0441\u043f\u0430\u0440\u0441\u0438\u0442\u044c \u043b\u043e\u0433\u0438 \u0432 \u0431\u0430\u0437\u0443\n"
    "\u2022 \u043f\u043e\u0431\u0443\u0434\u0443\u0454 \u0442\u0430\u0439\u043c\u043b\u0430\u0439\u043d (\u0445\u0440\u043e\u043d\u043e\u043b\u043e\u0433\u0456\u044e)\n"
    "\u2022 \u0437\u043d\u0430\u0439\u0434\u0435 IOC (IP, \u0434\u043e\u043c\u0435\u043d\u0438, \u0445\u0435\u0448\u0456, \u0442\u0443\u043b\u0438)\n"
    "\u2022 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c \u0434\u0435\u0442\u0435\u043a\u0442\u043e\u0440\u0438 (ransomware, RAT, RDP, persistence...)\n"
    "\u2022 \u0432\u0438\u0437\u043d\u0430\u0447\u0438\u0442\u044c \u0432\u0435\u043a\u0442\u043e\u0440 \u00ab\u044f\u043a \u0437\u0430\u0439\u0448\u043b\u0438\u00bb (\u0444\u0456\u0448\u0438\u043d\u0433 / RDP / USB)\n"
    "\u2022 \u0437\u0433\u0435\u043d\u0435\u0440\u0443\u0454 forensic-\u0437\u0432\u0456\u0442 \u0437 \u0432\u0438\u0441\u043d\u043e\u0432\u043a\u043e\u043c + \u0440\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u0430\u0446\u0456\u044f\u043c\u0438\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *3. \U0001F4AC \u041f\u0418\u0422\u0410\u041d\u041d\u042f \u041f\u041e \u041a\u0415\u0419\u0421\u0423* \u2501\u2501\u2501\u2501\u2501\n"
    "\u041e\u0431\u0435\u0440\u0438 \u043a\u0435\u0439\u0441 (\U0001F4C1 \u041c\u043e\u0457 \u043a\u0435\u0439\u0441\u0438) \u0456 \u043f\u0438\u0442\u0430\u0439 \u0437\u0432\u0438\u0447\u0430\u0439\u043d\u043e\u044e \u043c\u043e\u0432\u043e\u044e:\n"
    "\u2022 _\u042f\u043a \u0432\u0456\u0434\u0431\u0443\u0432\u0441\u044f \u043f\u043e\u0447\u0430\u0442\u043a\u043e\u0432\u0438\u0439 \u0434\u043e\u0441\u0442\u0443\u043f?_\n"
    "\u2022 _\u041f\u043e\u0431\u0443\u0434\u0443\u0439 \u0445\u0440\u043e\u043d\u043e\u043b\u043e\u0433\u0456\u044e \u0430\u0442\u0430\u043a\u0438_\n"
    "\u2022 _\u042f\u043a\u0456 IP \u0442\u0430 \u0434\u043e\u043c\u0435\u043d\u0438 \u0437\u043b\u043e\u0432\u043c\u0438\u0441\u043d\u0438\u043a\u0430?_\n"
    "\u2022 _\u042f\u043a\u0456 \u0456\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0438 \u0432\u0456\u0434\u0434\u0430\u043b\u0435\u043d\u043e\u0433\u043e \u0434\u043e\u0441\u0442\u0443\u043f\u0443?_\n"
    "\u2022 _\u0425\u0442\u043e \u0441\u0442\u0432\u043e\u0440\u0438\u0432 \u043d\u043e\u0432\u0456 \u0430\u043a\u0430\u0443\u043d\u0442\u0438? \u0429\u043e \u0447\u0438\u0441\u0442\u0438\u043b\u0438?_\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *4. \U0001F30D \u0417\u0410\u0413\u0410\u041b\u042c\u041d\u0418\u0419 \u041f\u041e\u0428\u0423\u041a (\u043f\u043e \u0432\u0441\u0456\u0445 \u043a\u0435\u0439\u0441\u0430\u0445)* \u2501\u2501\u2501\u2501\u2501\n"
    "\u0411\u0435\u0437 \u0432\u0438\u0431\u043e\u0440\u0443 \u043a\u0435\u0439\u0441\u0443 \u2014 \u0448\u0443\u043a\u0430\u0454 \u043f\u043e \u0412\u0421\u0406\u0425 \u0441\u043f\u0440\u0430\u0432\u0430\u0445:\n"
    "\u2022 _\u0412 \u044f\u043a\u0438\u0445 \u043a\u0435\u0439\u0441\u0430\u0445 \u0454 ngrok / rustdesk?_\n"
    "\u2022 _\u041a\u0435\u0439\u0441\u0438 \u0447\u0435\u0440\u0435\u0437 \u0444\u0456\u0448\u0438\u043d\u0433 / ransomware_\n"
    "\u2022 _\u0414\u0435 \u0437\u0433\u0430\u0434\u0443\u0454\u0442\u044c\u0441\u044f IP 1.2.3.4?_\n"
    "\U0001F1FA\U0001F1E6/\U0001F1F7\U0001F1FA/\U0001F1EC\U0001F1E7 \u041c\u043e\u0432\u0430: \u0443\u043a\u0440 / \u0440\u043e\u0441 / \u0430\u043d\u0433\u043b.\n"
    "\U0001F517 *Cross-case:* \u0437\u0430\u043b\u043b\u0454\u0448 \u043d\u043e\u0432\u0438\u0439 \u043a\u0435\u0439\u0441 \u2192 \u0431\u043e\u0442 \u0441\u043a\u0430\u0436\u0435 \u00ab\u0441\u0445\u043e\u0436\u0456 IOC \u0443 \u043a\u0435\u0439\u0441\u0456 X\u00bb.\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *5. \U0001F9F0 \u0406\u041d\u0421\u0422\u0420\u0423\u041c\u0415\u041d\u0422\u0418* \u2501\u2501\u2501\u2501\u2501\n"
    "\u041a\u043d\u043e\u043f\u043a\u0430 \u00ab\U0001F9F0 \u0406\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0438\u00bb:\n"
    "\u2022 \U0001F9EC YARA-\u0441\u043a\u0430\u043d \u0444\u0430\u0439\u043b\u0443 \u043d\u0430 \u043c\u0430\u043b\u0432\u0430\u0440\u044c\n"
    "\u2022 \U0001F310 \u041f\u0435\u0440\u0435\u043a\u043b\u0430\u0434 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0456\u0432 EN\u2192UK\n"
    "\u2022 \U0001F4C4 PDF: \u0437\u043d\u044f\u0442\u0438 \u043f\u0430\u0440\u043e\u043b\u044c / \u0432\u043e\u0434\u044f\u043d\u0438\u0439 \u0437\u043d\u0430\u043a / OCR\n"
    "\u2022 #\uFE0F\u20E3 \u0425\u0435\u0448\u0456, \U0001F3AF \u0432\u0438\u0442\u044f\u0433\u0442\u0438 IOC, \U0001F6E1 defang, \U0001F501 \u0434\u0435\u043a\u043e\u0434\n"
    "\u2022 \U0001F4E7 Email EML/MSG \u2192 \u0442\u0435\u043a\u0441\u0442\n"
    "\u2022 \U0001F50A \u0417\u0432\u0443\u043a+\u0442\u0440\u0430\u043d\u0441\u043a\u0440\u0438\u043f\u0442, \U0001F399 \u0434\u0456\u0430\u0440\u0438\u0437\u0430\u0446\u0456\u044f (\u0445\u0442\u043e-\u043a\u043e\u043b\u0438)\n"
    "\u2022 \U0001F5BC \u041f\u043e\u043a\u0440\u0430\u0449\u0435\u043d\u043d\u044f \u0444\u043e\u0442\u043e \u00d74, \U0001F697 \u0447\u0438\u0442\u0430\u043d\u043d\u044f \u043d\u043e\u043c\u0435\u0440\u0456\u0432\n"
    "\u2022 \U0001F4DA Book-\u0456\u043d\u0434\u0435\u043a\u0441 Study (offline)\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *7. \U0001F4CB \u041a\u041d\u041e\u041f\u041a\u0418 \u0413\u041e\u041b\u041e\u0412\u041d\u041e\u0413\u041e \u041c\u0415\u041d\u042e* \u2501\u2501\u2501\u2501\u2501\n"
    "\U0001F4C1 \u041c\u043e\u0457 \u043a\u0435\u0439\u0441\u0438 \u2014 \u0441\u043f\u0438\u0441\u043e\u043a \u0441\u043f\u0440\u0430\u0432 + \u0432\u0438\u0431\u0456\u0440 \u0430\u043a\u0442\u0438\u0432\u043d\u043e\u0433\u043e\n"
    "\U0001F4CB KAPE \u043b\u043e\u0433\u0438 \u2014 \u0437\u0430\u043b\u0438\u0442\u0438 KAPE CSV/JSON/ZIP \u0443 \u043a\u0435\u0439\u0441\n"
    "\U0001F4C4 \u0417\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0438\u0442\u0438 \u0437\u0432\u0456\u0442 \u2014 \u0434\u043e\u0434\u0430\u0442\u0438 PDF-\u0437\u0432\u0456\u0442 \u0443 \u0431\u0430\u0437\u0443 + \u0432\u0438\u0442\u044f\u0433\u043d\u0443\u0442\u0438 IOC (golden facts)\n"
    "\U0001F4E6 \u0412\u0435\u043b\u0438\u043a\u0435 \u0437\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0435\u043d\u043d\u044f \u2014 \u0434\u043b\u044f \u0432\u0435\u043b\u0438\u043a\u0438\u0445 \u0444\u0430\u0439\u043b\u0456\u0432 \u0447\u0435\u0440\u0435\u0437 \u0432\u0435\u0431-\u043b\u0456\u043d\u043a\n"
    "\U0001F4DA \u0411\u0430\u0437\u0430 \u0437\u043d\u0430\u043d\u044c \u2014 \u0437\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0435\u043d\u043d\u044f/\u043f\u0435\u0440\u0435\u0433\u043b\u044f\u0434/\u0432\u0438\u0434\u0430\u043b\u0435\u043d\u043d\u044f \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0456\u0432 KB\n"
    "\U0001F3AF Skills \u2014 \u0441\u043f\u0435\u0446-\u0431\u0430\u0437\u0430 \u0437\u043d\u0430\u043d\u044c \u0437\u0430 \u0442\u0435\u043c\u043e\u044e (\u2795 \u043d\u043e\u0432\u0438\u0439: /skill <\u043d\u0430\u0437\u0432\u0430>)\n"
    "\U0001F4CA \u0421\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043a\u0430 \u2014 \u043a\u0456\u043b\u044c\u043a\u0456\u0441\u0442\u044c \u043a\u0435\u0439\u0441\u0456\u0432/\u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0456\u0432/IOC\n"
    "\U0001F517 \u041f\u0435\u0440\u0435\u0441\u0456\u0447\u0435\u043d\u043d\u044f \u0437\u0432\u0456\u0442\u0456\u0432 \u2014 \u0441\u043f\u0456\u043b\u044c\u043d\u0456 IOC \u043c\u0456\u0436 \u043a\u0435\u0439\u0441\u0430\u043c\u0438 (\u0442\u043e\u0439 \u0441\u0430\u043c\u0438\u0439 \u0430\u0442\u0430\u043a\u0443\u0432\u0430\u043b\u044c\u043d\u0438\u043a)\n"
    "\U0001F5D1 \u0412\u0438\u0434\u0430\u043b\u0438\u0442\u0438 \u043a\u0435\u0439\u0441 \u2014 \u043f\u043e\u0432\u043d\u0435/\u043b\u043e\u0433\u0438/\u0437\u0432\u0456\u0442\u0438 (\u0430\u0434\u043c\u0456\u043d)\n"
    "\U0001F9EA Export FT JSONL \u2014 \u0435\u043a\u0441\u043f\u043e\u0440\u0442 train/eval \u0434\u043b\u044f fine-tune \u043c\u043e\u0434\u0435\u043b\u0456\n"
    "\u041a\u043e\u043c\u0430\u043d\u0434\u0438: /start (\u043c\u0435\u043d\u044e) \u00b7 /all \u0430\u0431\u043e /clear (\u0437\u0430\u0433\u0430\u043b\u044c\u043d\u0438\u0439 \u043f\u043e\u0448\u0443\u043a) \u00b7 /help (\u0446\u044f \u0434\u043e\u0432\u0456\u0434\u043a\u0430)\n\n"
    "\u2501\u2501\u2501\u2501\u2501 *6. \U0001F44D \u041d\u0410\u0412\u0427\u0410\u041d\u041d\u042f \u0411\u041e\u0422\u0410* \u2501\u2501\u2501\u2501\u2501\n"
    "\u041f\u0456\u0434 \u0432\u0456\u0434\u043f\u043e\u0432\u0456\u0434\u0434\u044e \u043a\u043d\u043e\u043f\u043a\u0438 \U0001F44D/\U0001F44E \u2014 \u0432\u0447\u0430\u0442\u044c \u0431\u043e\u0442\u0430 (\U0001F44D \u0437\u0430\u043f\u0430\u043c\u02bc\u044f\u0442\u0430\u0454, \U0001F44E \u0432\u0438\u043f\u0440\u0430\u0432\u0438\u0442\u044c\u0441\u044f).\n\n"
    "\u2139\uFE0F \u0417\u0430\u0433\u0430\u043b\u044c\u043d\u0456 \u043f\u0438\u0442\u0430\u043d\u043d\u044f \u0437 \u0444\u043e\u0440\u0435\u043d\u0437\u0456\u043a\u0438/\u043f\u0435\u043d\u0442\u0435\u0441\u0442\u0443 \u2014 \u0431\u043e\u0442 \u0432\u0456\u0434\u043f\u043e\u0432\u0456\u0441\u0442\u044c \u0437\u0456 \u0441\u0432\u043e\u0454\u0457 \u0431\u0430\u0437\u0438 (\u043a\u043d\u0438\u0433\u0438 + \u0434\u043e\u0441\u0432\u0456\u0434 \u0437\u0456 \u0441\u043f\u0440\u0430\u0432)."
)


# reusable \u00ab\u2b05\ufe0f \u041d\u0430\u0437\u0430\u0434\u00bb row -> reopens the Additional-Tools menu (no scrolling up)
_BACK_ROW = [{"text": "\u2b05\ufe0f \u041d\u0430\u0437\u0430\u0434 \u0434\u043e \u0456\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u0456\u0432",
              "callback_data": "addtools_menu"}]


def _back_kb(extra_rows=None):
    """Inline keyboard with a back-to-menu row (plus optional extra rows on top)."""
    rows = list(extra_rows or [])
    rows.append(_BACK_ROW)
    return {"inline_keyboard": rows}


def _collector_version_line():
    """One-line version/build/hash of the collector the bot serves (from its manifest)."""
    try:
        import io as _io, json as _j
        m = _j.load(_io.open('/data/dist/collector.json', encoding='utf-8'))
        v = m.get('version', '?')
        built = m.get('built', '')
        sh = (m.get('sha256') or '')[:12]
        sz = float(m.get('size_bytes') or 0) / 1024.0 / 1024.0
        return u'\U0001F4E6 \u0412\u0435\u0440\u0441\u0456\u044f: %s \u00b7 \u0437\u0431\u0456\u0440\u043a\u0430 %s \u00b7 %.0f \u041c\u0411 \u00b7 SHA256 %s\u2026 (\u043e\u0441\u0442\u0430\u043d\u043d\u044f)' % (v, built, sz, sh)
    except Exception:
        return u''


def _send_help(chat_id):
    """Send the help text rendered as Markdown; fall back to plain on any error."""
    import os as _os, json as _json, urllib.request as _u
    _vl = _collector_version_line()
    _text = HELP_MD.replace("http://CHANGE_ME_DFIR_LINK_IP:8080/collector.exe",
                            "http://CHANGE_ME_DFIR_LINK_IP:8080/collector.exe\n   " + _vl, 1) if _vl else HELP_MD
    _btn_txt = "\U0001F4E5 \u0417\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0438\u0442\u0438 \u043a\u043e\u043b\u0435\u043a\u0442\u043e\u0440 (EXE)"
    if _vl:
        try:
            _btn_txt += " " + _vl.split("\u00b7")[0].split(":")[-1].strip()
        except Exception:
            pass
    tok = _os.environ.get("DFIR_TG_BOT_TOKEN", "")
    if tok:
        try:
            _kb = {"inline_keyboard": [
                [{"text": _btn_txt,
                  "url": os.environ.get("DFIR_COLLECTOR_URL", "http://CHANGE_ME_DFIR_LINK_IP:8080/collector.exe")}],
                _BACK_ROW]}
            b = _json.dumps({"chat_id": chat_id, "text": _text,
                             "parse_mode": "Markdown", "reply_markup": _kb,
                             "disable_web_page_preview": True}).encode("utf-8")
            r = _u.urlopen(_u.Request("https://api.telegram.org/bot" + tok + "/sendMessage",
                           data=b, headers={"Content-Type": "application/json"}), timeout=15)
            if r.status == 200:
                return
        except Exception:
            pass
    _send_plain(chat_id, _text.replace("*", "").replace("_", "").replace("`", ""),
                reply_markup=_back_kb())


def _do_attacker_portrait(chat_id, refresh=False):
    """Cross-case attacker portrait — fire the case-maintainer endpoint (it does the
    IOC intersection + LLM synthesis and streams the result to Telegram itself).
    refresh=True forces a recompute (ignore cache)."""
    _send_plain(chat_id, ("\U0001F504 Перераховую портрет зловмисника…" if refresh
                          else "\U0001F575 Збираю пересічення IOC між усіма кейсами і будую портрет зловмисника… (~1–2 хв; далі — з кешу миттєво)"),
                reply_markup=_back_kb())

    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/attacker-portrait',
                             data=json.dumps({'chat_id': chat_id, 'refresh': bool(refresh)}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=400).read()
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, "❌ Портрет: помилка — " + str(e)[:150])

    threading.Thread(target=_work, daemon=True).start()


def _do_actor_list(chat_id):
    """Show DISTINCT attacker actors (cases split into separate attackers by strong shared
    indicators). Each button opens THAT actor's own portrait."""
    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/actor-list',
                             data=json.dumps({}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            d = json.loads(_u.urlopen(req, timeout=120).read())
            text = d.get('text') or '🕵 Немає акторів.'
            rows = [[{'text': '🕵 %s · %d кейс(и)' % (a['label'], a['n_cases']),
                      'callback_data': 'tool:actorportrait:%s' % a['uid']}]
                    for a in (d.get('actors') or [])]
            rows.append([{'text': '🔄 Оновити список', 'callback_data': 'tool:attacker_portrait'}])
            rows.append([{'text': '⬅️ Назад', 'callback_data': 'cross_reports'}])
            _send_plain(chat_id, text, reply_markup={'inline_keyboard': rows})
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, '❌ Список акторів: помилка — ' + str(e)[:150], reply_markup=_back_kb())
    threading.Thread(target=_work, daemon=True).start()


def _do_actor_portrait(chat_id, uid, refresh=False):
    """Build the portrait for ONE actor (its cluster of cases only)."""
    _send_plain(chat_id, ('\U0001F504 Перераховую портрет цього актора…' if refresh
                          else '\U0001F575 Будую портрет цього актора (його кейси)…'),
                reply_markup=_back_kb())

    def _work():
        try:
            import urllib.request as _u
            req = _u.Request('http://localhost:8787/actor-portrait',
                             data=json.dumps({'chat_id': chat_id, 'actor': uid, 'refresh': bool(refresh)}).encode('utf-8'),
                             headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=400).read()
        except Exception as e:                              # noqa: BLE001
            _send_plain(chat_id, '❌ Портрет актора: помилка — ' + str(e)[:150])

    threading.Thread(target=_work, daemon=True).start()


_FC_URL = os.environ.get('DFIR_SELF_URL', 'http://localhost:8787')
_FC_ADMIN = os.environ.get('DFIR_ADMIN_CHAT_ID', '')


def _fc_kb():
    return {'inline_keyboard': [[
        {'text': '\U0001F9F9 Новий чат', 'callback_data': 'tool:fc_new'},
        {'text': '⬅ Вихід', 'callback_data': 'tool:fc_exit'}]]}


def _fc_post(path, payload, timeout=90):
    import urllib.request as _u
    req = _u.Request(_FC_URL + path, data=json.dumps(payload).encode('utf-8'),
                     headers={'Content-Type': 'application/json'})
    return json.loads(_u.urlopen(req, timeout=timeout).read())


def _fc_warmup():
    """Почати завантаження моделі чату, поки користувач набирає перше повідомлення.

    Модель чату не резидентна: перший запит інакше чекає на перемикання і впирається
    в таймаут. Дрібний запит у фоні прибирає цю затримку з очей користувача.
    """
    def _go():
        try:
            import json as _j
            import urllib.request as _u
            url = os.getenv('DFIR_LLM_URL', 'http://192.168.100.1:1234') + '/v1/chat/completions'
            body = _j.dumps({'model': os.getenv('DFIR_FREECHAT_MODEL', 'agent-30b'),
                             'messages': [{'role': 'user', 'content': 'ok'}],
                             'max_tokens': 1}).encode()
            req = _u.Request(url, data=body, headers={'Content-Type': 'application/json'})
            _u.urlopen(req, timeout=600).read()
        except Exception:
            pass                      # прогрів — не привід турбувати користувача
    threading.Thread(target=_go, daemon=True).start()


def _do_free_chat_enter(chat_id, user_id):
    """ACL-gated entry into uncensored AI chat mode."""
    try:
        r = _fc_post('/free-chat/allowed', {'tg_id': chat_id}, timeout=15)
    except Exception:
        r = {'allowed': False}
    if not r.get('allowed'):
        _send_plain(chat_id, '⛔ Доступ до чату ШІ закрито. Заявку надіслано адміністратору.')
        if _FC_ADMIN and str(chat_id) != str(_FC_ADMIN):
            try:
                _send_plain(_FC_ADMIN, '\U0001F513 Користувач %s просить доступ до чату ШІ.' % chat_id,
                            reply_markup={'inline_keyboard': [[
                                {'text': '✅ Дати доступ', 'callback_data': 'tool:fcgrant:%s' % chat_id},
                                {'text': '❌', 'callback_data': 'tool:fcdeny:%s' % chat_id}]]})
            except Exception:
                pass
        return
    _set_pending(chat_id, user_id, 'free_chat', 'await_text')
    _fc_warmup()
    _send_plain(chat_id, '\U0001F513 Чат ШІ (без цензури). Пиши повідомлення.\n\U0001F9F9 Новий чат / ⬅ Вихід — кнопки нижче.', reply_markup=_fc_kb())


def _do_free_chat_msg(chat_id, user_id, text):
    """Run one turn in the background so long generations never block the webhook."""
    def _work():
        try:
            r = _fc_post('/free-chat/message', {'tg_id': chat_id, 'text': text}, timeout=660)
        except Exception as e:
            _send_plain(chat_id, '❌ Помилка: %s' % str(e)[:120], reply_markup=_fc_kb())
            return
        if r.get('ok'):
            _send_plain(chat_id, r.get('answer') or '(порожньо)', reply_markup=_fc_kb())
        else:
            reason = r.get('reason', '')
            msg = {'not_allowed': '⛔ Доступ закрито.',
                   'rate_limited': '⏳ Забагато повідомлень — спробуй пізніше.',
                   'model_loading': '⏳ Модель ще вантажиться (перший запит після паузи '
                                    'займає кілька хвилин). Надішли повідомлення ще раз.',
                   'llm_error': '❌ Помилка моделі.',
                   'empty_answer': '❌ Модель не відповіла.'}.get(reason, '❌ ' + str(reason))
            _send_plain(chat_id, msg, reply_markup=_fc_kb())
    threading.Thread(target=_work, daemon=True).start()


def handle_callback(chat_id, user_id, data):
    """Handle a 'tool:<name>' callback: set pending state + prompt for input."""
    if data == 'addtools_menu':
        handle_open_menu(chat_id)
        return
    if data.startswith('tool:act:'):
        # grammar: tool:act:<tool>:<choice>
        try:
            _, _, atool, choice = data.split(':', 3)
        except ValueError:
            _send_plain(chat_id, "❌ Невідома дія.")
            return
        st = _get_pending(chat_id, user_id)
        if not st or st.get('tool') != atool or st.get('stage') != 'await_choice':
            _send_plain(chat_id, "⌛ Сесія завершилась. Оберіть інструмент заново.")
            return
        # map choice -> existing st params each _do_* already reads
        if atool == 'translate':
            st['target'] = {'ua': 'українською', 'en': 'англійською'}.get(choice, 'українською')
            if choice == 'extract':
                st['extract_only'] = True
        elif atool == 'ocr':
            st['lang'] = choice
        _clear_pending(chat_id, user_id)
        FILE_DISPATCH[atool](chat_id, st)
        return
    if not data.startswith('tool:'):
        return
    tool = data.split(':', 1)[1]
    # feedback loop (S3): interactive report claim verification
    if tool.startswith('fbstart:'):
        try:
            from analysis.report_feedback import start_review
            start_review(chat_id, user_id, tool.split(':', 1)[1])
        except Exception as _fbe:
            _send_plain(chat_id, '❌ Помилка перевірки: ' + str(_fbe)[:120])
        return
    if tool.startswith('fbv:'):
        try:
            from analysis.report_feedback import handle_verdict
            handle_verdict(chat_id, user_id, tool.split(':', 1)[1])
        except Exception:
            pass
        return
    if tool.startswith('addrep:'):
        try:
            from analysis.report_feedback import _is_trusted
            if not _is_trusted(user_id):
                _send_plain(chat_id, '🔒 Лише для авторизованих аналітиків.')
                return
        except Exception:
            pass
        _job = tool.split(':', 1)[1]
        def _work_addrep():
            try:
                import urllib.request as _u
                _u.urlopen(_u.Request('http://localhost:8787/dfir-report-to-case',
                    data=json.dumps({'job_id': _job, 'chat_id': chat_id}).encode('utf-8'),
                    headers={'Content-Type': 'application/json'}), timeout=200).read()
            except Exception as _e:
                _send_plain(chat_id, '❌ Не вдалось додати звіт: ' + str(_e)[:120])
        threading.Thread(target=_work_addrep, daemon=True).start()
        _send_plain(chat_id, '⏳ Додаю звіт у памʼять кейсу…')
        return
    # Manual-IOC approval (like) / cancel — grammar tool:ioccommit:<id> / tool:ioccancel:<id>.
    if tool.startswith('ioccommit:') or tool.startswith('ioccancel:'):
        _pid = tool.split(':', 1)[1]
        _ep = 'commit' if tool.startswith('ioccommit:') else 'cancel'
        _clear_pending(chat_id, user_id)   # acting on a card exits IOC-add mode (multi-paste done)

        def _work_ioc():
            try:
                import urllib.request as _u
                req = _u.Request('http://localhost:8787/ioc-manual/' + _ep,
                                 data=json.dumps({'chat_id': chat_id, 'id': _pid}).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'})
                _u.urlopen(req, timeout=120).read()
            except Exception as e:                          # noqa: BLE001
                _send_plain(chat_id, '❌ Помилка: ' + str(e)[:150])
        threading.Thread(target=_work_ioc, daemon=True).start()
        return
    if tool == 'help':
        _send_help(chat_id)
        return
    if tool in ('llm_big_on', 'llm_big_off'):
        _do_agent_mode(chat_id, tool == 'llm_big_on')
        return
    if tool in ('llm_off', 'llm_on', 'llm_status'):
        _do_llm_toggle(chat_id, tool.replace('llm_', ''))
        return
    if tool == 'llm_agent_help':
        _send_llm_agent_help(chat_id)
        return
    if tool == 'attacker_portrait':
        _do_actor_list(chat_id)          # → list of SEPARATE actors (each opens its own portrait)
        return
    if tool.startswith('actorportrait:'):
        _rest = tool.split(':', 1)[1]    # <uid> or <uid>:refresh
        _ref = _rest.endswith(':refresh')
        _uid = _rest[:-8] if _ref else _rest
        _do_actor_portrait(chat_id, _uid, refresh=_ref)
        return
    if tool == 'portrait_refresh':
        _do_attacker_portrait(chat_id, refresh=True)
        return
    if tool == 'fstree':
        def _work_fst():
            try:
                import urllib.request as _u
                _u.urlopen(_u.Request('http://localhost:8787/case-fstree',
                                      data=json.dumps({'chat_id': chat_id}).encode('utf-8'),
                                      headers={'Content-Type': 'application/json'}), timeout=300).read()
            except Exception as _e:                          # noqa: BLE001
                _send_plain(chat_id, '❌ Дерево тек: ' + str(_e)[:150])
        threading.Thread(target=_work_fst, daemon=True).start()
        _send_plain(chat_id, '🌳 Будую дерево тек активного кейсу з таблиці $MFT (кілька секунд)…')
        return
    if tool == 'misp_all':
        _do_misp_export_all(chat_id)
        return
    if tool == 'misp_export':
        _do_misp_export(chat_id)
        return
    if tool == 'free_chat':
        _do_free_chat_enter(chat_id, user_id)
        return
    if tool == 'fc_exit':
        _clear_pending(chat_id, user_id)
        _send_plain(chat_id, '✅ Вихід із чату ШІ.',
                    reply_markup={'inline_keyboard': [[{'text': '⬅ Меню', 'callback_data': 'addtools_menu'}]]})
        return
    if tool == 'fc_new':
        try:
            _fc_post('/free-chat/reset', {'tg_id': chat_id}, timeout=15)
        except Exception:
            pass
        _send_plain(chat_id, '\U0001F9F9 Новий чат. Пиши повідомлення.', reply_markup=_fc_kb())
        return
    if tool.startswith('fcgrant:'):
        if _FC_ADMIN and str(chat_id) == str(_FC_ADMIN):
            _tid = tool.split(':', 1)[1]
            _set_pending(chat_id, user_id, 'fc_name', 'await_text', target=_tid)
            _send_plain(chat_id, '✏ Напиши імʿя/підпис для юзера %s (так ти бачитимеш його у WebUI):' % _tid)
        return
    if tool.startswith('fcdeny:'):
        if _FC_ADMIN and str(chat_id) == str(_FC_ADMIN):
            _send_plain(chat_id, '❌ Заявку відхилено.')
        return
    if tool not in TOOL_PROMPT_UA:
        _send_plain(chat_id, "❌ Невідомий інструмент.")
        return
    if tool in ('pdf_translate', 'translate'):
        # web-upload link flow (no 20MB limit, no filesystem access)
        _send_translate_upload_link(chat_id)
        return
    if tool == 'audio_translate_ua':
        # EN audio -> UA voice via web-upload link (any size; avoids the 20MB
        # Telegram cap and the getFile path entirely).
        _send_audiotr_upload_link(chat_id)
        return
    if tool == 'bookidx_index':
        # web-upload link flow -> bookidx_inbox -> bookidx-watcher (offline)
        _send_bookidx_upload_link(chat_id)
        return
    if tool == 'book_mp3':
        # book -> UA-voice MP3 via web-upload link (any size, avoids 20MB TG cap)
        _send_book_upload_link(chat_id)
        return
    kind = TOOL_INPUT_KIND.get(tool, 'file')
    stage = 'await_file' if kind == 'file' else 'await_text'
    _set_pending(chat_id, user_id, tool, stage)
    # back/cancel button so the user isn't stuck waiting for a file with no way out
    _send_plain(chat_id, TOOL_PROMPT_UA[tool],
                reply_markup=_back_kb([[{"text": "❌ Скасувати", "callback_data": "addtools_menu"}]]))



def _send_translate_upload_link(chat_id):
    """Send the user their personal web-upload link for document translation.
    No 20MB Telegram limit, no filesystem access — upload over the VPN, the bot
    routes the file to the translator and notifies here when done."""
    key = "tooljob-translate-%s" % chat_id
    base = os.environ.get("DFIR_UPLOAD_BASE", "http://CHANGE_ME_DFIR_LINK_IP:8080")
    url = "%s/?case_key=%s&mode=misc&chat_id=%s" % (base, key, chat_id)
    _send_plain(chat_id,
        "\U0001F310 \u041f\u0435\u0440\u0435\u043a\u043b\u0430\u0434 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430 (EN\u2192UK, \u0431\u0443\u0434\u044c-\u044f\u043a\u0438\u0439 \u0440\u043e\u0437\u043c\u0456\u0440):\n\n"
        "1\ufe0f\u20e3 \u0412\u0456\u0434\u043a\u0440\u0438\u0439 \u0446\u0435 \u043f\u043e\u0441\u0438\u043b\u0430\u043d\u043d\u044f \u043f\u043e VPN:\n%s\n\n"
        "2\ufe0f\u20e3 \u0417\u0430\u043b\u0438\u0439 PDF (\u0431\u0435\u0437 \u043b\u0456\u043c\u0456\u0442\u0443 20\u041c\u0411).\n"
        "3\ufe0f\u20e3 \u042f \u043d\u0430\u043f\u0438\u0448\u0443 \u00ab\u0437\u0430\u0432\u0430\u043d\u0442\u0430\u0436\u0435\u043d\u043e \u2713\u00bb, \u043f\u0435\u0440\u0435\u043a\u043b\u0430\u0434\u0443 \u0456 \u043d\u0430\u0434\u0456\u0448\u043b\u044e \u043b\u0456\u043d\u043a \u043d\u0430 \u0440\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442." % url)



def _send_audiotr_upload_link(chat_id):
    """Web-upload link for EN-audio -> UK-voice translation (no 20MB limit)."""
    key = 'tooljob-audiotr-%s' % chat_id
    base = os.environ.get('DFIR_UPLOAD_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080')
    url = '%s/?case_key=%s&mode=misc&chat_id=%s' % (base, key, chat_id)
    _send_plain(chat_id,
        '🌐🇺🇦 Аудіо англ→укр голосом (будь-який розмір):' + chr(10) + chr(10) +
        '1️⃣ Відкрий лінк по VPN:' + chr(10) + url + chr(10) + chr(10) +
        '2️⃣ Залий АНГЛОМОВНЕ аудіо/відео (без ліміту 20МБ).' + chr(10) +
        '3️⃣ Я розпізнаю → перекладу → озвучу і надішлю MP3 + текст сюди.')


def _send_bookidx_upload_link(chat_id):
    """Send the user their personal web-upload link for the BOOKIDX index. The
    file is routed to bookidx_inbox and processed offline by the bookidx-watcher."""
    key = "tooljob-bookidx-%s" % chat_id
    base = os.environ.get("DFIR_UPLOAD_BASE", "http://CHANGE_ME_DFIR_LINK_IP:8080")
    url = "%s/?case_key=%s&mode=misc&chat_id=%s" % (base, key, chat_id)
    _send_plain(chat_id,
        "\U0001F4DA Book-\u0456\u043d\u0434\u0435\u043a\u0441 Study (offline, \u0431\u0443\u0434\u044c-\u044f\u043a\u0438\u0439 \u0440\u043e\u0437\u043c\u0456\u0440):\n\n"
        "1\ufe0f\u20e3 \u0412\u0456\u0434\u043a\u0440\u0438\u0439 \u0446\u0435 \u043f\u043e\u0441\u0438\u043b\u0430\u043d\u043d\u044f \u043f\u043e VPN:\n%s\n\n"
        "2\ufe0f\u20e3 \u0417\u0430\u043b\u0438\u0439 PDF (\u044f\u043a\u0449\u043e \u0437 \u043f\u0430\u0440\u043e\u043b\u0435\u043c \u2014 \u0432\u043a\u0430\u0436\u0438 \u0439\u043e\u0433\u043e \u0443 \u0444\u043e\u0440\u043c\u0456).\n"
        "3\ufe0f\u20e3 \u042f \u043d\u0430\u0434\u0456\u0448\u043b\u044e \u043b\u0456\u043d\u043a \u043d\u0430 ZIP \u0437 \u0434\u0432\u043e\u043c\u043e\u0432\u043d\u0438\u043c \u0456\u043d\u0434\u0435\u043a\u0441\u043e\u043c \u0442\u0430 cheat-sheet." % url)


def _send_book_upload_link(chat_id):
    """Web-upload link for book->MP3 audiobook (EPUB/PDF/FB2/DOCX/TXT, any size).
    File is routed to _do_book_mp3; result MP3 + text delivered by link (the
    shared audio_results dir auto-prunes after DFIR_AUDIO_RESULTS_KEEP_DAYS)."""
    key = 'tooljob-book-%s' % chat_id
    base = os.environ.get('DFIR_UPLOAD_BASE', 'http://CHANGE_ME_DFIR_LINK_IP:8080')
    url = '%s/?case_key=%s&mode=misc&chat_id=%s' % (base, key, chat_id)
    _send_plain(chat_id,
        '\U0001F4D6\U0001F50A Книга в MP3 (EPUB/PDF/FB2/DOCX/TXT, будь-який розмір):' + chr(10) + chr(10) +
        '1\ufe0f\u20e3 Відкрий лінк по VPN:' + chr(10) + url + chr(10) + chr(10) +
        '2\ufe0f\u20e3 Залий книгу (без ліміту 20МБ).' + chr(10) +
        '3\ufe0f\u20e3 Я озвучу українським голосом і надішлю MP3 + текст сюди.' + chr(10) +
        '(Читаю текст «як є», без перекладу — для англомовних книг спершу переклади документ.)')


def request_translate_password(chat_id, filename):
    """Ask the user for the PDF password (called by the translate watcher when it
    finds a protected file). Sets a pending state so the next text reply is captured
    and written next to the file so the watcher can retry."""
    _set_pending(chat_id, chat_id, '__translate_pw', 'await_pw', tr_file=filename)
    _send_plain(chat_id, "\U0001F510 \u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442 \u00ab%s\u00bb \u0437\u0430\u0445\u0438\u0449\u0435\u043d\u0438\u0439 \u043f\u0430\u0440\u043e\u043b\u0435\u043c.\n\u041d\u0430\u0434\u0456\u0448\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c \u043f\u043e\u0432\u0456\u0434\u043e\u043c\u043b\u0435\u043d\u043d\u044f\u043c \u2014 \u0456 \u044f \u043f\u0440\u043e\u0434\u043e\u0432\u0436\u0443 \u043f\u0435\u0440\u0435\u043a\u043b\u0430\u0434." % filename)


def request_bookidx_password(chat_id, filename):
    """Ask for the PDF password (called by the bookidx-watcher on an encrypted
    file). The reply is written next to the file in bookidx_inbox so the watcher
    retries."""
    _set_pending(chat_id, chat_id, '__bookidx_pw', 'await_pw', tr_file=filename)
    _send_plain(chat_id, "\U0001F510 PDF \u00ab%s\u00bb \u0437\u0430\u0445\u0438\u0449\u0435\u043d\u0438\u0439 \u043f\u0430\u0440\u043e\u043b\u0435\u043c.\n\u041d\u0430\u0434\u0456\u0448\u043b\u0438 \u043f\u0430\u0440\u043e\u043b\u044c \u043f\u043e\u0432\u0456\u0434\u043e\u043c\u043b\u0435\u043d\u043d\u044f\u043c \u2014 \u043f\u0440\u043e\u0434\u043e\u0432\u0436\u0443 \u0456\u043d\u0434\u0435\u043a\u0441\u0430\u0446\u0456\u044e." % filename)


def handle_message(chat_id, user_id, message: dict):
    """Handle a document/text message while a tool is pending for this user.

    Returns True if the message was consumed by a tool, False otherwise (so the
    caller / n8n can fall through to normal bot handling)."""
    st = _get_pending(chat_id, user_id)
    if not st:
        return False
    tool = st['tool']
    st['user_id'] = user_id

    # ---- second-stage parameter collection (password / watermark text / target)
    if st['stage'] == 'await_pw' and tool == 'pdf_unlock':
        st['password'] = (message.get('text') or '').strip()
        st['stage'] = 'run'
        _clear_pending(chat_id, user_id)
        _do_pdf_unlock(chat_id, st)
        return True

    if st['stage'] == 'await_pw' and tool == 'bookidx_index':
        st['password'] = (message.get('text') or '').strip()
        st['stage'] = 'run'
        _clear_pending(chat_id, user_id)
        _do_bookidx_index(chat_id, st)
        return True

    if st['stage'] == 'await_pw' and tool == '__bookidx_pw':
        pw = (message.get('text') or '').strip()
        _clear_pending(chat_id, user_id)
        try:
            import os as _os
            inbox = _os.environ.get('BOOKIDX_INBOX', '/bookidx_inbox')
            dst = _os.path.join(inbox, st.get('tr_file') or '')
            with open(dst + '.password', 'w', encoding='utf-8') as _pf:
                _pf.write(pw)
            try:
                _os.remove(dst + '.needpass')
            except Exception:
                pass
            _send_plain(chat_id, "\U0001F511 \u041f\u0430\u0440\u043e\u043b\u044c \u043e\u0442\u0440\u0438\u043c\u0430\u043d\u043e \u2014 \u043f\u0440\u043e\u0434\u043e\u0432\u0436\u0443\u044e \u0456\u043d\u0434\u0435\u043a\u0441\u0430\u0446\u0456\u044e.")
        except Exception as _e:
            _send_plain(chat_id, "\u274c \u041d\u0435 \u0432\u0434\u0430\u043b\u043e\u0441\u044c \u0437\u0431\u0435\u0440\u0435\u0433\u0442\u0438 \u043f\u0430\u0440\u043e\u043b\u044c: " + str(_e)[:120])
        return True

    if st['stage'] == 'await_count' and tool == 'diarize':
        import re as _re_c
        _t = (message.get('text') or '').strip().lower()
        _m = _re_c.search(r'\d+', _t)
        st['num_speakers'] = _m.group(0) if (_m and _t not in ('авто', 'auto', '')) else ''
        st['stage'] = 'run'
        _clear_pending(chat_id, user_id)
        _do_diarize(chat_id, st)
        return True

    # ---- file-input tools
    if st['stage'] == 'await_file':
        doc = message.get('document')
        photo = message.get('photo')
        # Telegram delivers an mp3/wav/m4a sent from the music picker as `audio`,
        # a recorded voice note as `voice`, and clips as `video`/`video_note`/
        # `animation` — NOT as `document`. The old handler only read document/photo,
        # so any audio/video arrived as "no file" → "Очікую файл" (the reported mp3 bug).
        audio = message.get('audio')
        voice = message.get('voice')
        video = message.get('video')
        video_note = message.get('video_note')
        animation = message.get('animation')
        file_id = None
        orig_name = 'file.bin'
        if doc:
            file_id = doc.get('file_id'); orig_name = doc.get('file_name', 'file.bin')
        elif audio:
            _aext = (audio.get('mime_type') or '').split('/')[-1] or 'mp3'
            file_id = audio.get('file_id')
            orig_name = audio.get('file_name') or ((audio.get('title') or 'audio') + '.' + _aext)
        elif voice:
            file_id = voice.get('file_id'); orig_name = 'voice.ogg'
        elif video:
            file_id = video.get('file_id'); orig_name = video.get('file_name') or 'video.mp4'
        elif video_note:
            file_id = video_note.get('file_id'); orig_name = 'videonote.mp4'
        elif animation:
            file_id = animation.get('file_id'); orig_name = animation.get('file_name') or 'animation.mp4'
        elif photo:  # photos arrive as an array of sizes; take the largest
            file_id = photo[-1].get('file_id'); orig_name = 'photo.jpg'
        if not file_id:
            _send_plain(chat_id, "❗ Очікую файл. Надішліть аудіо, відео, фото або документ.")
            return True
        workdir = _new_workdir()
        try:
            local = _tg_download(file_id, workdir)
        except ValueError as e:
            _send_plain(chat_id, SIDECAR_ERR_UA.get(str(e), "❌ Помилка завантаження файлу."))
            _cleanup(workdir); _clear_pending(chat_id, user_id)
            return True
        st.update({'file_path': local, 'orig_name': orig_name, 'workdir': workdir})

        # diarize: ask how many speakers FIRST (operative usually knows; this
        # fixes auto over-clustering that invented 30 speakers for a 2-3 person call)
        if tool == 'diarize':
            st['stage'] = 'await_count'; st['ts'] = time.time()
            _send_plain(chat_id, "🔢 Скільки осіб у розмові? Надішліть число (напр. 2 або 3) — або «авто», якщо не знаєте.")
            return True

        # pdf_unlock needs a password next -> ask, keep pending
        if tool == 'pdf_unlock':
            st['stage'] = 'await_pw'; st['ts'] = time.time()
            _send_plain(chat_id, "🔑 Введіть пароль до PDF (наступним повідомленням):")
            return True

        # tools that benefit from an LLM-suggested choice: ASK first
        if tool in ASK_TOOLS:
            try:
                _m = _sidecar_post('/meta', st['file_path'])
                _mj = _m.json() if _m.status_code == 200 else {}
            except Exception:
                _mj = {}
            _md = _mj.get('meta', {}) or {}
            # /meta returns kind at TOP level; meta dict holds page_count and,
            # for images, _size=[w,h]. Derive a non-PII summary (no content).
            _size = _md.get('_size') or [None, None]
            meta_summary = {
                'kind': _mj.get('kind'),
                'pages': _md.get('page_count'),
                'width': _size[0] if isinstance(_size, (list, tuple)) and len(_size) > 0 else None,
                'height': _size[1] if isinstance(_size, (list, tuple)) and len(_size) > 1 else None,
            }
            meta_summary = {k: v for k, v in meta_summary.items() if v is not None}
            opts = _llm_suggest_actions(tool, json.dumps(meta_summary, ensure_ascii=False))
            st['stage'] = 'await_choice'
            st['ts'] = time.time()
            _send_plain(chat_id, "🤖 Я переглянув документ. Що зробити?",
                        reply_markup=_ask_actions_keyboard(tool, opts))
            return True

        # all other file tools run immediately
        _clear_pending(chat_id, user_id)
        FILE_DISPATCH[tool](chat_id, st)
        return True

    # ---- text-input tools
    if st['stage'] == 'await_text':
        text = message.get('text') or ''
        if not text:
            _send_plain(chat_id, "❗ Очікую текст.")
            return True
        if tool == 'free_chat':
            st['ts'] = time.time()          # persistent chat mode; exit clears it
            _do_free_chat_msg(chat_id, user_id, text)
            return True
        if tool == 'fc_name':
            _tid = st.get('target')
            _clear_pending(chat_id, user_id)
            try:
                _fc_post('/free-chat/acl', {'admin_id': chat_id, 'action': 'grant',
                                            'tg_id': _tid, 'name': text.strip()[:120]}, timeout=15)
                _send_plain(chat_id, '✅ Доступ надано: %s (%s)' % (text.strip()[:120], _tid))
                if _tid:
                    _send_plain(_tid, '✅ Тобі відкрито чат ШІ. Натисни «\U0001F513 Чат ШІ» у меню.')
            except Exception as _e:
                _send_plain(chat_id, '❌ Не вдалось: %s' % str(_e)[:120])
            return True
        st['text'] = text
        if tool == 'ioc_add':
            # Telegram splits a long paste into several messages ~1s apart. Keep the pending
            # active (refresh ts) so EACH chunk yields its own preview card — nothing is lost.
            # Auto-expires via PENDING_TTL; the ✅/❌ approval callback clears it.
            st['ts'] = time.time()
        else:
            _clear_pending(chat_id, user_id)
        TEXT_DISPATCH[tool](chat_id, st)
        return True

    return False


# =============================================================================
#  Flask wiring — register endpoints the n8n CB Router calls
# =============================================================================
def register_addtools(app, *, tg_send_plain, TG_BOT_TOKEN, build_chat_payload,
                      LLM_URL, LLM_MODEL,
                      WINDOWS_AGENT_URL=None, WINDOWS_AGENT_TOKEN=None):
    """Inject the bot's helpers and register the addtools HTTP endpoints.

    Call once from app.py after those symbols are defined."""
    global log
    _CTX.update({
        'tg_send_plain': tg_send_plain,
        'TG_BOT_TOKEN': TG_BOT_TOKEN,
        'build_chat_payload': build_chat_payload,
        'LLM_URL': LLM_URL,
        'LLM_MODEL': LLM_MODEL,
        'WINDOWS_AGENT_URL': WINDOWS_AGENT_URL,
        'WINDOWS_AGENT_TOKEN': WINDOWS_AGENT_TOKEN,
    })
    log = app.logger
    _start_tmp_janitor()

    from flask import request, jsonify

    @app.post('/addtools/menu')
    def _addtools_menu():
        data = request.get_json(force=True, silent=True) or {}
        chat_id = str(data.get('chat_id') or '').strip()
        if not chat_id:
            return jsonify({'ok': False, 'error': 'chat_id required'}), 400
        handle_open_menu(chat_id)
        return jsonify({'ok': True})

    @app.post('/addtools/cb')
    def _addtools_cb():
        """n8n posts a tool:* (or addtools_menu) callback here."""
        data = request.get_json(force=True, silent=True) or {}
        chat_id = str(data.get('chat_id') or '').strip()
        user_id = str(data.get('user_id') or chat_id).strip()
        cb_data = str(data.get('data') or '').strip()
        if not chat_id or not cb_data:
            return jsonify({'ok': False, 'error': 'chat_id and data required'}), 400
        if _tool_from_cb(cb_data) in _ADMIN_ONLY_TOOLS and chat_id not in _LLM_ADMIN_IDS:
            # a stale button from an old menu: refuse, do not load anything on the GPUs
            try:
                _send_plain(chat_id, '🔒 Цей інструмент доступний лише адміністратору. '
                      'Бот зосереджений на DFIR-аналізі справ.', reply_markup=_back_kb())
            except Exception:
                pass
            return jsonify({'ok': True, 'refused': 'admin_only'})
        handle_callback(chat_id, user_id, cb_data)
        return jsonify({'ok': True})

    @app.post('/addtools/message')
    def _addtools_message():
        """n8n posts a message (document/text) here ONLY when a tool is pending
        for (chat_id,user_id). Returns consumed=true/false so the router can
        fall through to normal handling when this module didn't own the message."""
        data = request.get_json(force=True, silent=True) or {}
        chat_id = str(data.get('chat_id') or '').strip()
        user_id = str(data.get('user_id') or chat_id).strip()
        message = data.get('message') or {}
        if not chat_id:
            return jsonify({'ok': False, 'error': 'chat_id required'}), 400
        consumed = handle_message(chat_id, user_id, message)
        return jsonify({'ok': True, 'consumed': bool(consumed)})

    @app.get('/addtools/pending')
    def _addtools_pending():
        """Lets n8n cheaply ask 'is a tool waiting for this user?' so it only
        routes raw messages here when needed."""
        chat_id = str(request.args.get('chat_id') or '').strip()
        user_id = str(request.args.get('user_id') or chat_id).strip()
        st = _get_pending(chat_id, user_id)
        return jsonify({'ok': True, 'pending': bool(st),
                        'tool': st.get('tool') if st else None,
                        'stage': st.get('stage') if st else None})

    @app.get('/addtools/health')
    def _addtools_health():
        ok = False
        try:
            with httpx.Client(timeout=5) as c:
                ok = c.get(f'{SIDECAR_URL}/health').status_code == 200
        except Exception:
            ok = False
        return jsonify({'ok': True, 'sidecar_reachable': ok, 'sidecar_url': SIDECAR_URL})

    log.info("[addtools] registered: /addtools/{menu,cb,message,pending,health}")
    return app


def _start_tmp_janitor():
    """Sweep leaked tool tempdirs (addtools_* / meta_ / yara_) older than the TTL —
    per-tool _cleanup already wipes on success; this catches crashes so uploaded
    (possibly malicious) files never pile up. Runs every 30 min in a daemon."""
    import glob as _glob, tempfile as _tf
    ttl = int(os.getenv('DFIR_TOOLS_TMP_TTL', '3600'))

    def _sweep():
        while True:
            try:
                now = time.time()
                for pat in ('addtools_*', 'meta_*', 'yara_*', 'cf_*', 'rdpcache_*'):
                    for d in _glob.glob(os.path.join(_tf.gettempdir(), pat)):
                        try:
                            if now - os.path.getmtime(d) > ttl:
                                shutil.rmtree(d, ignore_errors=True)
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(1800)
    threading.Thread(target=_sweep, daemon=True).start()
