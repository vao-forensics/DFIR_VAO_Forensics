#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
 PDF → українська: ЛОКАЛЬНИЙ читабельний переклад захищених PDF (EN → UK)
==============================================================================

Самодостатній рушій перекладу. Один файл. Передається як є на іншу машину.
Нижче — повне пояснення ЯК і ЧОМУ це працює саме так (для людини й для ШІ,
що інтегруватиме це в бота).

------------------------------------------------------------------------------
ЩО ЦЕ РОБИТЬ
------------------------------------------------------------------------------
Бере захищені паролем PDF (англійською), і для кожної сторінки робить:
  1) розшифровує PDF паролем (pikepdf);
  2) РЕНДЕРИТЬ сторінку як картинку (зберігає фото/схеми/водяний знак 1-в-1);
  3) ВИТЯГУЄ чистий текст сторінки БЕЗ водяного знаку;
  4) ПЕРЕКЛАДАЄ текст локальною LLM (Ollama або LM Studio) EN→UK;
  5) складає читабельний HTML: ліворуч оригінал-картинка, праворуч переклад.
Результат — по одному index.html на книгу. Відновлюваний (resume) посторінково.

------------------------------------------------------------------------------
ЧОМУ САМЕ ТАК (важливі рішення, перевірені на практиці)
------------------------------------------------------------------------------
• ПРИВАТНІСТЬ: зміст іде ТІЛЬКИ в локальну LLM на твоєму залізі. Нічого не
  вивантажується в інтернет/хмару. Це головна вимога — документи не можна
  заливати нікуди. Тому хмарні перекладачі НЕ годяться:
  щоб модель у хмарі переклала — текст довелося б відправити в хмару.

• ЧИТАБЕЛЬНІСТЬ, НЕ ТОЧНА ВЕРСТКА: пробували pdf2zh (реконструкція верстки) —
  крихко: ламало макет, «налазив» текст, водяний знак потрапляв у переклад і
  псував його. Відмовились. Формат «картинка оригіналу + чистий переклад поруч»
  дає найкращий результат для НАВЧАННЯ: бачиш оригінал, читаєш українською.

• ВОДЯНИЙ ЗНАК: у цих PDF (Study) водяний знак — це текст шрифтом 'Helvetica'
  та/або ПОВЕРНУТІ (діагональні) рядки. Якщо його не відсікти, LLM перекладає
  кашу типу «Forensic [ВЛАСНИК 1234] analysis of [ВЛАСНИК 1234] memory...».
  Рішення: при витягу тексту ПРОПУСКАЄМО спани зі шрифтом Helvetica і повернуті
  рядки. Так водяний знак НЕ потрапляє в переклад, але ЛИШАЄТЬСЯ видимим на
  картинці-оригіналі (його НЕ видаляємо — це позначка власника/копірайт).
  >>> Якщо в інших документах водяний знак іншим шрифтом — зміни IS_WATERMARK().

• ОДНА СТОРІНКА = ОДИН ЗАПИТ (не по абзацу!): дрібні фрагменти (заголовок на
  3 слова) «зносили» модель — на вході 74 симв., на виході 1800 симв. марення.
  Переклад цілої сторінки одним запитом дає контекст і стабільність.
  + NUM_PREDICT обмежує довжину відповіді ~ за розміром входу (захист від марення).
  + Дуже щільні сторінки ріжемо на чанки <= MAXCHARS, щоб влізали в контекст.

• ВІДНОВЛЮВАНІСТЬ: кожна готова сторінка — окремий файл frag/pNNNN.html.
  Перезапуск пропускає вже готові. Жоден збій не починає з нуля.

• НАДІЙНІСТЬ: запити до LLM з повторами (мережа/перезавантаження моделі не
  валять процес). На проді крутили як systemd-службу з Restart, а вивід писали
  на ЛОКАЛЬНИЙ диск + окремо синхронізували в спільну папку (бо пряме писання
  в мережеву/спільну папку падало, коли вона відпадала).

------------------------------------------------------------------------------
ЗАЛЕЖНОСТІ
------------------------------------------------------------------------------
  python3 -m venv venv && ./venv/bin/pip install pymupdf pikepdf requests

------------------------------------------------------------------------------
ЗАПУСК
------------------------------------------------------------------------------
  PDF_DIR=. PDF_PASSWORD='пароль' \
  LLM_ENDPOINT=http://localhost:11434 LLM_BACKEND=ollama LLM_MODEL=qwen2.5:32b \
  WORKERS=3 OUT_DIR=./output_ua \
  ./venv/bin/python course_translate.py

Змінні середовища (усі опційні, мають дефолти):
  PDF_DIR        тека з PDF (за замовч. поточна)            [.]
  PDF_PASSWORD   пароль до PDF (порожньо = не зашифровані)  ['']
  OUT_DIR        куди писати результат                      [./output_ua]
  LLM_BACKEND    'ollama' або 'openai' (LM Studio = openai) [ollama]
  LLM_ENDPOINT   базовий URL LLM-сервера                    [http://localhost:11434]
  LLM_MODEL      назва моделі                                [qwen2.5:32b]
  WORKERS        скільки сторінок паралельно (потужні карти→6-8) [3]
  DPI            роздільність картинок-оригіналів            [130]
  NUM_CTX        контекст LLM на запит                       [4096]

------------------------------------------------------------------------------
ЯК ІНТЕГРУВАТИ В БОТА (підказка для ШІ)
------------------------------------------------------------------------------
• Функція translate(text) — це і є «двигун». Дай боту PDF+пароль → виклич
  process_book() на файл, або translate() на довільний текст.
• Для швидкості на багатьох картах: підніми LLM_BACKEND=openai на LM Studio з
  моделлю, що ПОВНІСТЮ влазить в одну карту (напр. qwen2.5:14b ~9ГБ у 16ГБ —
  qwen2.5:32b ~20ГБ В ОДНУ 16ГБ-карту НЕ влазить → частина на CPU → повільно!).
  Або 32b з розподілом на 2 карти (tensor split). Тоді став WORKERS=6-8.
• Backend 'openai' працює з будь-яким OpenAI-сумісним сервером (LM Studio, vLLM).
==============================================================================
"""
import os
import sys
import time
import glob
import html
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import fitz        # PyMuPDF
import pikepdf

# ----------------------------- КОНФІГ ----------------------------------------
PDF_DIR     = os.environ.get("PDF_DIR", ".")
PDF_PASSWORD= os.environ.get("PDF_PASSWORD", "")
OUT_DIR     = os.environ.get("OUT_DIR", "./output_ua")
BACKEND     = os.environ.get("LLM_BACKEND", "openai").lower()      # ollama | openai
ENDPOINT    = os.environ.get("LLM_ENDPOINT", "http://192.168.100.1:1234").rstrip("/")
MODEL       = os.environ.get("LLM_MODEL", "translate-9b")
WORKERS     = int(os.environ.get("WORKERS", "3"))
DPI         = int(os.environ.get("DPI", "130"))
NUM_CTX     = int(os.environ.get("NUM_CTX", "4096"))
MAXCHARS    = 3000           # макс символів тексту на один запит до LLM
DECDIR      = os.path.join(OUT_DIR, "_decrypted")   # кеш розшифрованих копій

SYSTEM_PROMPT = (
    "Ти професійний перекладач технічної літератури з цифрової криміналістики (DFIR). "
    "Перекладай англійський текст підручника українською мовою точно й природно. "
    "Загальновживані технічні терміни можеш лишати в дужках англійською. "
    "Зберігай поділ на абзаци. Виводь ЛИШЕ переклад, без коментарів і вступних фраз."
)

_lock = threading.Lock()     # для логів та збірки index.html
_tl = threading.local()      # thread-local відкриті PDF (fitz не потоково-безпечний)


# ----------------------------- ЛОГ -------------------------------------------
def log(msg: str):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    with _lock:
        sys.stderr.write(line + "\n"); sys.stderr.flush()
        try:
            with open(os.path.join(OUT_DIR, "_progress.txt"), "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


# -------------------- ВОДЯНИЙ ЗНАК: що відсікати -----------------------------
def is_watermark(span: dict, line_rotated: bool) -> bool:
    """Чи цей текстовий спан — водяний знак (його НЕ перекладаємо).
    Тут: повернуті (діагональні) рядки АБО шрифт 'Helvetica'.
    >>> Адаптуй під свій документ, якщо знак іншим шрифтом/кольором."""
    if line_rotated:
        return True
    return span.get("font", "").startswith("Helvetica")


# -------------------- ВИТЯГ ЧИСТОГО ТЕКСТУ -----------------------------------
def page_paragraphs(page: "fitz.Page") -> list:
    """Текст сторінки в порядку читання, без водяного знаку. Список абзаців."""
    paras = []
    for block in page.get_text("dict").get("blocks", []):
        if block.get("type", 0) != 0:          # 0 = текстовий блок (1 = картинка)
            continue
        buf = []
        for line in block.get("lines", []):
            d = line.get("dir", (1, 0))
            rotated = abs(d[1]) > 0.01          # напрям не горизонтальний → повернуто
            words = [s["text"] for s in line.get("spans", [])
                     if not is_watermark(s, rotated)]
            if words:
                buf.append("".join(words))
        text = " ".join(buf).strip()
        if len(text) >= 3:
            paras.append(text)
    return paras


def chunk_paragraphs(paras: list) -> list:
    """Об'єднати абзаци в чанки <= MAXCHARS (щоб влізали в контекст LLM)."""
    chunks, cur = [], ""
    for p in paras:
        if len(p) > MAXCHARS:                   # дуже довгий абзац — ріжемо жорстко
            for i in range(0, len(p), MAXCHARS):
                chunks.append(p[i:i + MAXCHARS])
            continue
        if len(cur) + len(p) + 2 > MAXCHARS:
            if cur:
                chunks.append(cur)
            cur = p
        else:
            cur = (cur + "\n\n" + p) if cur else p
    if cur:
        chunks.append(cur)
    return chunks


# -------------------- ПЕРЕКЛАД (Ollama / OpenAI-сумісний) --------------------
def _post(payload: dict) -> str:
    """Один HTTP-запит до LLM. Повертає текст або кидає виняток."""
    if BACKEND == "openai":          # LM Studio / vLLM / OpenAI-сумісний
        url = ENDPOINT + "/v1/chat/completions"
        r = requests.post(url, json=payload, timeout=(10, 600))
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()
    else:                             # ollama (нативний /api/generate)
        url = ENDPOINT + "/api/generate"
        r = requests.post(url, json=payload, timeout=(10, 600))
        r.raise_for_status()
        out = r.json().get("response", "").strip()
        if not out:
            raise ValueError("порожня відповідь")
        return out


def translate(text: str) -> str:
    """Перекласти шматок тексту EN→UK з повторами при збоях.
    NUM_PREDICT обмежує довжину відповіді ~ за входом (захист від «марення»)."""
    if not text.strip():
        return ""
    predict = min(2048, max(256, len(text) // 2))
    if BACKEND == "openai":
        payload = {
            "model": MODEL, "temperature": 0.2, "max_tokens": predict,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": text}],
        }
    else:
        payload = {
            "model": MODEL, "system": SYSTEM_PROMPT, "prompt": text, "stream": False,
            "options": {"temperature": 0.2, "num_ctx": NUM_CTX, "num_predict": predict},
        }
    attempt = 0
    while True:
        attempt += 1
        try:
            return _post(payload)
        except Exception as e:
            wait = min(60, 5 * attempt)
            if attempt <= 40:
                log(f"   повтор перекладу #{attempt} через {wait}с: {e}")
                time.sleep(wait)
            else:
                log(f"   ⚠️ не вдалось перекласти після {attempt} спроб — лишаю оригінал")
                return text          # не втрачаємо сторінку


def translate_page_text(paras: list) -> str:
    """Перекласти всю сторінку (по чанках), зберігаючи поділ на абзаци."""
    return "\n\n".join(translate(c) for c in chunk_paragraphs(paras))


# -------------------- HTML: складання index.html -----------------------------
def build_index(out_dir: str, title: str, total: int):
    frags = sorted(glob.glob(os.path.join(out_dir, "frag", "p*.html")))
    t = html.escape(title)
    head = ("<!doctype html><meta charset=utf-8><title>" + t + "</title><style>"
            "body{font-family:sans-serif;margin:0;background:#222;color:#eee}"
            "h2{padding:10px 16px;background:#111;margin:0;position:sticky;top:0}"
            ".pg{display:flex;gap:16px;padding:16px;border-bottom:2px solid #444}"
            ".col{flex:1}.col img{width:100%;border:1px solid #555}"
            ".tr{background:#2c2c2c;padding:16px;border-radius:8px;line-height:1.6}"
            ".tr p{margin:0 0 10px}h3{color:#8cf;margin:4px 0}</style>"
            "<h2>" + t + " — готово " + str(len(frags)) + " / " + str(total) + " стор.</h2>")
    body = "".join(open(f, encoding="utf-8").read() for f in frags)
    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(head + body)


# -------------------- РОЗШИФРУВАННЯ ------------------------------------------
def decrypt_pdf(src: str) -> str:
    """Розшифрувати PDF паролем у кеш DECDIR; повернути шлях до розшифрованого."""
    os.makedirs(DECDIR, exist_ok=True)
    name = os.path.splitext(os.path.basename(src))[0]
    dec = os.path.join(DECDIR, name + ".pdf")
    if os.path.exists(dec):
        return dec
    with pikepdf.open(src, password=PDF_PASSWORD) as pdf:   # пароль '' теж ок
        pdf.save(dec)
    log(f"розшифровано: {name}")
    return dec


# -------------------- ОБРОБКА ОДНІЄЇ СТОРІНКИ (потік) ------------------------
def _get_doc(dec_path: str) -> "fitz.Document":
    cache = getattr(_tl, "docs", None)
    if cache is None:
        cache = _tl.docs = {}
    if dec_path not in cache:
        cache[dec_path] = fitz.open(dec_path)
    return cache[dec_path]


def process_page(dec_path: str, pno: int, out_dir: str, total: int, name: str):
    frag = os.path.join(out_dir, "frag", f"p{pno + 1:04}.html")
    if os.path.exists(frag) and os.path.getsize(frag) > 0:
        return                                   # вже готово (resume)
    page = _get_doc(dec_path)[pno]
    img_path = os.path.join(out_dir, "img", f"p{pno + 1:04}.png")
    if not os.path.exists(img_path):
        page.get_pixmap(dpi=DPI).save(img_path)  # оригінал-картинка (фото+знак)
    paras = page_paragraphs(page)                # чистий текст без знаку
    t0 = time.time()
    uk = translate_page_text(paras)
    dt = time.time() - t0
    tr_html = "".join(f"<p>{html.escape(p)}</p>" for p in uk.split("\n\n") if p.strip())
    with open(frag, "w", encoding="utf-8") as f:
        f.write(f"<div class=pg><div class=col><h3>Оригінал — стор.{pno + 1}</h3>"
                f"<img src='img/p{pno + 1:04}.png'></div>"
                f"<div class=col><h3>Переклад — стор.{pno + 1}</h3>"
                f"<div class=tr>{tr_html}</div></div></div>")
    log(f"{name}: стор.{pno + 1}/{total} ({sum(len(p) for p in paras)} симв., {dt:.0f}с)")


# -------------------- ОБРОБКА ОДНІЄЇ КНИГИ -----------------------------------
def process_book(src_pdf: str):
    name = os.path.splitext(os.path.basename(src_pdf))[0]
    out_dir = os.path.join(OUT_DIR, name)
    os.makedirs(os.path.join(out_dir, "img"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "frag"), exist_ok=True)
    dec = decrypt_pdf(src_pdf)
    doc = fitz.open(dec); total = doc.page_count; doc.close()
    pending = [p for p in range(total)
               if not os.path.exists(os.path.join(out_dir, "frag", f"p{p + 1:04}.html"))]
    log(f"=== КНИГА: {name} ({total} стор., до роботи {len(pending)}) ===")
    counter = [0]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(process_page, dec, p, out_dir, total, name) for p in pending]
        for fut in as_completed(futs):
            fut.result()                          # підніме виняток, якщо був
            with _lock:
                counter[0] += 1
                if counter[0] % 5 == 0:
                    build_index(out_dir, name, total)
    build_index(out_dir, name, total)
    log(f"✅ КНИГА ГОТОВА: {name}")


# ----------------------------- MAIN ------------------------------------------
def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    pdfs = sorted(glob.glob(os.path.join(PDF_DIR, "*.pdf")))
    if not pdfs:
        sys.exit(f"Не знайдено PDF у {PDF_DIR}")
    log(f"СТАРТ. backend={BACKEND} model={MODEL} endpoint={ENDPOINT} "
        f"workers={WORKERS} pdfs={len(pdfs)}")
    for src in pdfs:
        try:
            process_book(src)
        except Exception as e:
            log(f"⚠️ помилка в {os.path.basename(src)}: {e} — далі")
    log("🏁 УВЕСЬ ПАКЕТ ЗАВЕРШЕНО")


if __name__ == "__main__":
    main()
