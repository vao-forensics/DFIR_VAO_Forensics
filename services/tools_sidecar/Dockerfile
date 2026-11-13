# =============================================================================
#  tools-sidecar — DFIR "Додаткові інструменти" native-library sidecar
# -----------------------------------------------------------------------------
#  WHY a sidecar (Option B from the design doc):
#  The main bot container is python:3.12-ALPINE (musl libc). Forensic wheels
#  such as pikepdf (libqpdf), PyMuPDF, ocrmypdf (Tesseract + Ghostscript) ship
#  glibc/manylinux wheels and native deps that are painful to compile on Alpine.
#  Debian "slim-bookworm" is glibc, so every wheel + apt package "just works",
#  and the heavy/native code is ISOLATED from the lean forensic analyzer.
#
#  This image exposes a tiny internal HTTP API (Flask) on port 8799, reachable
#  ONLY on the internal docker network `dfir-net` (no host port published).
#  The case-maintainer (Alpine) bot proxies uploaded files here over httpx.
# =============================================================================
FROM python:3.12-slim-bookworm

# --- OS-level native dependencies (glibc) ------------------------------------
#  qpdf           -> backend C++ engine behind pikepdf (PDF decrypt/save)
#  tesseract-ocr  -> OCR engine used by ocrmypdf
#  *-ukr / *-eng  -> Ukrainian + English language packs (DFIR docs are bilingual)
#  *-osd          -> orientation/script detection data (deskew/rotate)
#  ghostscript    -> required by ocrmypdf for PDF rendering / PDF-A output
#  unpaper        -> optional image clean-up step used by ocrmypdf --clean
#  pngquant       -> optional lossy image optimization for ocrmypdf output
#  libqpdf-dev    -> not needed at runtime (wheel bundles it) but harmless to omit
#  fonts-dejavu   -> deterministic font for any PyMuPDF text rendering
#  fonts-liberation -> LiberationSerif = metric Times clone w/ full Cyrillic;
#                      used as NOTO_FONT_PATH for pdf2zh (font closer to original)
RUN apt-get update && apt-get install -y --no-install-recommends \
        qpdf \
        tesseract-ocr \
        tesseract-ocr-ukr \
        tesseract-ocr-eng \
        tesseract-ocr-osd \
        ghostscript \
        unpaper \
        pngquant \
        fonts-dejavu-core \
        fonts-liberation \
        libgl1 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python dependencies ------------------------------------------------------
#  Pinned to current stable lines (2026-06). All ship glibc wheels on Debian.
#  NB: ocrmypdf pulls pikepdf + pdfminer.six transitively, but we pin explicitly
#  so the version surface is auditable.
#  pdf2zh==1.9.11 -> layout-preserving EN->UK PDF translation (PDFMathTranslate),
#                    talks to the host gemma-2-9b-translate via OpenAI API.
# NB: pdf2zh==1.9.11 pins pymupdf<1.25.3 while its babeldoc dep needs
#     pymupdf>=1.25.1, so PyMuPDF is bumped to 1.25.2 (the version proven in the
#     host pdf2zh venv). pikepdf is left unpinned so the resolver can satisfy
#     both ocrmypdf and pdf2zh (host venv resolved pikepdf 10.x). The sidecar's
#     own fitz/pikepdf usage is API-stable across these bumps.
RUN pip install --no-cache-dir \
        "flask==3.0.3" \
        "gunicorn==22.0.0" \
        "PyMuPDF==1.25.2" \
        "ocrmypdf==16.5.0" \
        "python-docx==1.1.2" \
        "extract-msg==0.54.1" \
        "pillow==11.0.0" \
        "pdf2zh==1.9.11" \
        "impacket==0.12.0"

# --- pdf2zh assets baked into the image --------------------------------------
#  GoNotoKurrent  -> CJK/fallback font pdf2zh expects in its font cache; baked so
#                    there is no first-run network font download.
#  dfir_pdf2zh_prompt.txt -> DFIR glossary + anti-hyphenation custom prompt.
#  config.json    -> service creds fallback (OPENAI_* env overlays this at run
#                    time via translator.set_envs). NOTO_FONT_PATH points at the
#                    LiberationSerif (Times-like) face for output closer to the
#                    original; the runtime env overrides it if set.
#  doclayout YOLO ONNX -> page-layout model babeldoc needs; baked at the cache
#  path it verifies (HOME=/root) so there is NO first-run HuggingFace download.
COPY GoNotoKurrent-Regular.ttf /app/GoNotoKurrent-Regular.ttf
COPY dfir_pdf2zh_prompt.txt /app/dfir_pdf2zh_prompt.txt
# official source (Hugging Face), pinned by SHA-256
RUN python3 -c "import urllib.request,hashlib,sys; u,d,h=sys.argv[1:4]; urllib.request.urlretrieve(u,d); x=hashlib.sha256(open(d,'rb').read()).hexdigest(); sys.exit(0 if x==h else 'sha256 mismatch: '+d)" \
    https://huggingface.co/wybxc/DocLayout-YOLO-DocStructBench-onnx/resolve/main/doclayout_yolo_docstructbench_imgsz1024.onnx /app/doclayout_yolo_docstructbench_imgsz1024.onnx fece9af02f618b603ff7921ccec6861d13e7e1f9830e091dfb7e8ad9311e5b21
RUN mkdir -p /root/.cache/babeldoc/fonts /root/.cache/babeldoc/models \
    && cp /app/doclayout_yolo_docstructbench_imgsz1024.onnx /root/.cache/babeldoc/models/doclayout_yolo_docstructbench_imgsz1024.onnx \
    && cp /app/GoNotoKurrent-Regular.ttf /root/.cache/babeldoc/fonts/GoNotoKurrent-Regular.ttf \
    && mkdir -p /root/.config/PDFMathTranslate \
    && printf '%s' '{"NOTO_FONT_PATH":"/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf","translators":[{"name":"openai","envs":{"OPENAI_BASE_URL":"http://192.168.134.1:1234/v1","OPENAI_API_KEY":"sk-local","OPENAI_MODEL":"gemma-2-9b-translate"}}]}' > /root/.config/PDFMathTranslate/config.json

COPY bmc-tools.py /opt/bmc-tools.py
RUN pip install --no-cache-dir openpyxl
RUN pip install --no-cache-dir yara-python
RUN pip install --no-cache-dir pefile

# --- audio-translate-ua tool: EN audio -> UK spoken MP3 ----------------------
#  ffmpeg   -> WAV->MP3 encode (voice-grade 22050 Hz mono) for the /audio-translate-ua
#              pipeline (Whisper transcript -> translate-9b -> Piper TTS -> MP3).
#  piper-tts-> offline neural TTS (onnxruntime CPU); the uk_UA voice is baked in
#              below so there is NO first-run model download.
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "piper-tts==1.4.2"
#  Ukrainian voice (grapheme model, 22050 Hz). ~77 MB onnx + json, persistent in
#  the image (survives container recreate; /tmp is ephemeral tmpfs).
# official Piper voice (rhasspy/piper-voices), pinned by SHA-256
RUN mkdir -p /app/voices
RUN python3 -c "import urllib.request,hashlib,sys; u,d,h=sys.argv[1:4]; urllib.request.urlretrieve(u,d); x=hashlib.sha256(open(d,'rb').read()).hexdigest(); sys.exit(0 if x==h else 'sha256 mismatch: '+d)" \
    https://huggingface.co/rhasspy/piper-voices/resolve/main/uk/uk_UA/ukrainian_tts/medium/uk_UA-ukrainian_tts-medium.onnx /app/voices/uk_UA-ukrainian_tts-medium.onnx 7920419ac5f6fd8b6450520f24b52ed5a319cb53dd018fbcd71c9e079cbac84f
COPY voices/uk_UA-ukrainian_tts-medium.onnx.json /app/voices/uk_UA-ukrainian_tts-medium.onnx.json

COPY bookidx /app/bookidx
COPY course_translate.py /app/course_translate.py
COPY dfir_rules.yar /app/dfir_rules.yar
COPY app.py .

# Internal-only port; never published to the host (see docker-compose.snippet).
EXPOSE 8799

# Single worker (jobs are CPU-bound and serialized), generous timeout for OCR of
# large scans, threaded so /health stays responsive while a job runs.
CMD ["gunicorn", "--bind", "0.0.0.0:8799", \
     "--workers", "1", "--worker-class", "gthread", "--threads", "4", \
     "--timeout", "1200", "--keep-alive", "5", "app:app"]
