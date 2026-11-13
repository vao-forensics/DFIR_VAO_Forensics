"""Chain-of-Custody / Evidence Hash Manifest.

Compliance-critical module for the DFIR case-maintainer service.

Responsibilities
----------------
1. On every uploaded file, compute MD5 / SHA1 / SHA256 + size and append a row
   to a *hash-chained* `case_evidence` Postgres table. Each row embeds the
   SHA256 of the previous row (``prev_row_hash``) and its own ``row_hash`` so the
   whole evidence log is tamper-evident: editing or deleting any historic row
   breaks the seal and ``verify_chain()`` will report exactly where.
2. Generate a court-ready "Chain of Custody" PDF manifest (reportlab) that lists
   every evidence item with its hashes, ingest time, uploader and the chain
   seal (final row hash + verification status).

Design notes / conventions (match the existing codebase)
--------------------------------------------------------
* Config-first: DSN and timezone come from ``core.config`` — no hardcoded
  secrets, no hardcoded DSN.
* DB access uses the thin ``psycopg2.connect(PG_DSN)`` + ``autocommit`` pattern
  used everywhere else in app.py / ioc_extract.py.
* reportlab is already installed; the container image ships ttf-dejavu, so we
  register DejaVuSans for proper Cyrillic (Ukrainian) rendering in the PDF.
* User-facing strings are Ukrainian; internal/log strings are short and never
  leak secrets or absolute internal paths to the user.
* Drop this file in ``analysis/`` (the Dockerfile COPYs ``analysis/``).

Public API
----------
    ensure_schema()                         -> create table + indexes (idempotent)
    record_evidence(...)                    -> hash a file + append a chained row
    verify_chain(case_key=None)             -> (ok: bool, report: dict)
    build_manifest_pdf(case_key)            -> bytes (PDF) | None
    list_evidence(case_key)                 -> list[dict]
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
from datetime import datetime, timezone

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger("app")

# Timezone used for *display* in the PDF. The DB always stores UTC (timestamptz).
DISPLAY_TZ = os.getenv("DFIR_DISPLAY_TZ", "Europe/Kyiv")

# Read files in chunks so a multi-GB image never has to fit in RAM.
_HASH_CHUNK = 1024 * 1024  # 1 MiB

# Genesis marker for the very first row of a case's chain. A fixed, well-known
# constant makes the chain deterministic and independently re-computable.
_GENESIS = "0" * 64


# ───────────────────────────────────────────────────────────────────────────
# Schema
# ───────────────────────────────────────────────────────────────────────────
def ensure_schema() -> None:
    """Create the `case_evidence` table and its indexes (idempotent).

    Columns
    -------
    seq            BIGSERIAL  — global monotonic insert order (chain order).
    case_key       text       — owning case.
    file_name      text       — original (sanitised) file name as uploaded.
    stored_path    text       — server-side path where the artefact lives.
    size_bytes     bigint
    md5/sha1/sha256 text       — lower-case hex digests.
    uploader_chat  text       — Telegram chat_id of the uploader (string-safe).
    source         text       — ingest channel (tusd / store-file / telegram…).
    ingested_at    timestamptz— server ingest time (UTC).
    prev_row_hash  text       — sha256 of the previous row in THIS case's chain.
    row_hash       text       — sha256 over this row's canonical field tuple.

    The pair (prev_row_hash, row_hash) forms a per-case hash chain. ``seq`` keeps
    a global, gap-revealing order; deleting a row leaves a gap AND breaks the
    successor's prev_row_hash link.
    """
    ddl = """
    CREATE TABLE IF NOT EXISTS public.case_evidence (
        seq            BIGSERIAL PRIMARY KEY,
        case_key       text        NOT NULL,
        file_name      text        NOT NULL,
        stored_path    text,
        size_bytes     bigint      NOT NULL DEFAULT 0,
        md5            text        NOT NULL,
        sha1           text        NOT NULL,
        sha256         text        NOT NULL,
        uploader_chat  text,
        source         text,
        ingested_at    timestamptz NOT NULL DEFAULT now(),
        prev_row_hash  text        NOT NULL,
        row_hash       text        NOT NULL,
        UNIQUE (case_key, row_hash)
    );
    CREATE INDEX IF NOT EXISTS idx_case_evidence_case
        ON public.case_evidence (case_key, seq);
    CREATE INDEX IF NOT EXISTS idx_case_evidence_sha256
        ON public.case_evidence (sha256);
    """
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(ddl)


# ───────────────────────────────────────────────────────────────────────────
# Hashing helpers
# ───────────────────────────────────────────────────────────────────────────
def hash_file(path: str) -> dict:
    """Stream a file once and return {md5, sha1, sha256, size_bytes}.

    Single pass over the bytes — efficient for large disk images / memory dumps.
    """
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "size_bytes": size,
    }


def _compute_row_hash(
    *,
    case_key: str,
    file_name: str,
    size_bytes: int,
    md5: str,
    sha1: str,
    sha256: str,
    uploader_chat: str,
    source: str,
    ingested_at_iso: str,
    prev_row_hash: str,
) -> str:
    """Compute the canonical SHA256 seal for one evidence row.

    The field order here IS the contract: ``verify_chain`` recomputes with the
    exact same order, so changing it would invalidate every stored chain. Use a
    NUL separator (cannot appear in any of the textual fields) to avoid field-
    boundary ambiguity (e.g. "ab"+"c" vs "a"+"bc").
    """
    canonical = "\x00".join(
        [
            case_key,
            file_name,
            str(size_bytes),
            md5,
            sha1,
            sha256,
            uploader_chat or "",
            source or "",
            ingested_at_iso,
            prev_row_hash,
        ]
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ───────────────────────────────────────────────────────────────────────────
# Append to chain
# ───────────────────────────────────────────────────────────────────────────
def record_evidence(
    *,
    case_key: str,
    file_path: str,
    file_name: str | None = None,
    uploader_chat: str | int | None = None,
    source: str = "upload",
) -> dict:
    """Hash ``file_path`` and append a tamper-evident row to ``case_evidence``.

    Idempotent on (case_key, sha256): if the exact same bytes were already
    recorded for this case we return the existing row instead of duplicating it.

    Returns the inserted (or existing) row as a dict, plus ``{"duplicate": bool}``.
    Raises FileNotFoundError if the artefact is missing — callers should treat a
    missing file as an ingest failure, never silently skip custody.
    """
    if not case_key:
        raise ValueError("case_key required")
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    ensure_schema()

    digests = hash_file(file_path)
    fname = (file_name or os.path.basename(file_path)).strip() or "uploaded.bin"
    uploader = "" if uploader_chat is None else str(uploader_chat)
    ingested_at = datetime.now(timezone.utc)
    ingested_at_iso = ingested_at.isoformat()

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = False  # transactional: read tip + append atomically
        try:
            with conn.cursor() as cur:
                # De-dup: same bytes already in custody for this case.
                cur.execute(
                    "SELECT seq, sha256, row_hash, file_name "
                    "FROM public.case_evidence "
                    "WHERE case_key=%s AND sha256=%s LIMIT 1",
                    (case_key, digests["sha256"]),
                )
                existing = cur.fetchone()
                if existing:
                    conn.rollback()
                    return {
                        "duplicate": True,
                        "seq": existing[0],
                        "case_key": case_key,
                        "sha256": existing[1],
                        "row_hash": existing[2],
                        "file_name": existing[3],
                        **digests,
                    }

                # Lock the case's chain tip so two concurrent uploads cannot read
                # the same prev_row_hash and fork the chain. FOR UPDATE serialises
                # appends per case_key. (gunicorn runs --workers 1, but tusd +
                # background threads can still race, so we lock defensively.)
                cur.execute(
                    "SELECT row_hash FROM public.case_evidence "
                    "WHERE case_key=%s ORDER BY seq DESC LIMIT 1 FOR UPDATE",
                    (case_key,),
                )
                tip = cur.fetchone()
                prev_row_hash = tip[0] if tip else _GENESIS

                row_hash = _compute_row_hash(
                    case_key=case_key,
                    file_name=fname,
                    size_bytes=digests["size_bytes"],
                    md5=digests["md5"],
                    sha1=digests["sha1"],
                    sha256=digests["sha256"],
                    uploader_chat=uploader,
                    source=source,
                    ingested_at_iso=ingested_at_iso,
                    prev_row_hash=prev_row_hash,
                )

                cur.execute(
                    """
                    INSERT INTO public.case_evidence
                        (case_key, file_name, stored_path, size_bytes,
                         md5, sha1, sha256, uploader_chat, source,
                         ingested_at, prev_row_hash, row_hash)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING seq
                    """,
                    (
                        case_key, fname, file_path, digests["size_bytes"],
                        digests["md5"], digests["sha1"], digests["sha256"],
                        uploader, source, ingested_at, prev_row_hash, row_hash,
                    ),
                )
                seq = cur.fetchone()[0]
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    _log.info("[evidence] case=%s seq=%s sha256=%s recorded",
              case_key, seq, digests["sha256"][:12])
    return {
        "duplicate": False,
        "seq": seq,
        "case_key": case_key,
        "file_name": fname,
        "uploader_chat": uploader,
        "source": source,
        "ingested_at": ingested_at_iso,
        "prev_row_hash": prev_row_hash,
        "row_hash": row_hash,
        **digests,
    }


# ───────────────────────────────────────────────────────────────────────────
# Verify chain
# ───────────────────────────────────────────────────────────────────────────
def verify_chain(case_key: str | None = None) -> tuple[bool, dict]:
    """Re-walk the chain and confirm it is intact.

    If ``case_key`` is given, verify just that case; otherwise verify every case
    independently (one chain per case_key).

    Returns ``(ok, report)`` where report = {
        "cases": { case_key: {"rows": n, "ok": bool, "broken_at_seq": seq|None,
                              "seal": <final row_hash>|None } },
        "ok": bool,
    }.
    A break is reported the moment a recomputed row_hash differs from the stored
    one, or a prev_row_hash does not match the predecessor's row_hash.
    """
    ensure_schema()
    report: dict = {"cases": {}, "ok": True}

    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            if case_key:
                cur.execute(
                    "SELECT DISTINCT case_key FROM public.case_evidence "
                    "WHERE case_key=%s",
                    (case_key,),
                )
            else:
                cur.execute("SELECT DISTINCT case_key FROM public.case_evidence")
            cases = [r[0] for r in cur.fetchall()]

            for ck in cases:
                cur.execute(
                    """
                    SELECT seq, file_name, size_bytes, md5, sha1, sha256,
                           uploader_chat, source, ingested_at,
                           prev_row_hash, row_hash
                    FROM public.case_evidence
                    WHERE case_key=%s ORDER BY seq ASC
                    """,
                    (ck,),
                )
                rows = cur.fetchall()
                ok = True
                broken_at = None
                expected_prev = _GENESIS
                seal = None

                for r in rows:
                    (seq, fname, size_b, md5, sha1, sha256, uploader,
                     source, ingested_at, prev_hash, stored_row_hash) = r

                    # Link check: this row must chain to the previous row_hash.
                    if prev_hash != expected_prev:
                        ok = False
                        broken_at = seq
                        break

                    # Integrity check: recompute the row seal from its fields.
                    recomputed = _compute_row_hash(
                        case_key=ck,
                        file_name=fname,
                        size_bytes=size_b,
                        md5=md5,
                        sha1=sha1,
                        sha256=sha256,
                        uploader_chat=uploader or "",
                        source=source or "",
                        ingested_at_iso=ingested_at.astimezone(timezone.utc).isoformat(),
                        prev_row_hash=prev_hash,
                    )
                    if recomputed != stored_row_hash:
                        ok = False
                        broken_at = seq
                        break

                    expected_prev = stored_row_hash
                    seal = stored_row_hash

                report["cases"][ck] = {
                    "rows": len(rows),
                    "ok": ok,
                    "broken_at_seq": broken_at,
                    "seal": seal,
                }
                if not ok:
                    report["ok"] = False

    return report["ok"], report


def list_evidence(case_key: str) -> list[dict]:
    """Return all evidence rows for a case, in chain order, as dicts."""
    ensure_schema()
    out: list[dict] = []
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT seq, file_name, size_bytes, md5, sha1, sha256,
                       uploader_chat, source, ingested_at, prev_row_hash, row_hash
                FROM public.case_evidence
                WHERE case_key=%s ORDER BY seq ASC
                """,
                (case_key,),
            )
            cols = [d[0] for d in cur.description]
            for row in cur.fetchall():
                out.append(dict(zip(cols, row)))
    return out


# ───────────────────────────────────────────────────────────────────────────
# PDF manifest
# ───────────────────────────────────────────────────────────────────────────
def _register_unicode_font():
    """Register DejaVuSans (shipped via apk ttf-dejavu) for Cyrillic output.

    Returns the font family name to use, falling back to Helvetica (Latin only)
    if the TTF cannot be found so the manifest still renders.
    """
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",  # alpine ttf-dejavu path
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
    ]
    bold_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
    ]
    reg = next((p for p in candidates if os.path.exists(p)), None)
    if not reg:
        return "Helvetica"
    try:
        pdfmetrics.registerFont(TTFont("DejaVuSans", reg))
        bold = next((p for p in bold_candidates if os.path.exists(p)), None)
        if bold:
            pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold))
        return "DejaVuSans"
    except Exception:
        return "Helvetica"


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def build_manifest_pdf(case_key: str) -> bytes | None:
    """Build a court-ready Chain-of-Custody PDF for ``case_key``.

    Returns PDF bytes, or None if the case has no evidence rows. Embeds the full
    hash table, ingest metadata, and the chain seal + live verification result.
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    rows = list_evidence(case_key)
    if not rows:
        return None

    chain_ok, report = verify_chain(case_key)
    case_report = report["cases"].get(case_key, {})
    seal = case_report.get("seal")

    font = _register_unicode_font()
    bold_font = "DejaVuSans-Bold" if font == "DejaVuSans" else "Helvetica-Bold"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CoCTitle", parent=styles["Heading1"], fontName=bold_font,
        fontSize=16, spaceAfter=4, alignment=TA_LEFT,
    )
    h2_style = ParagraphStyle(
        "CoCH2", parent=styles["Heading2"], fontName=bold_font,
        fontSize=11, spaceBefore=6, spaceAfter=4,
    )
    small = ParagraphStyle(
        "CoCSmall", parent=styles["Normal"], fontName=font, fontSize=8,
    )
    mono = ParagraphStyle(
        "CoCMono", parent=styles["Normal"], fontName=font, fontSize=6.5,
        leading=8,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=14 * mm, bottomMargin=16 * mm,
        title=f"Chain of Custody — {case_key}",
    )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    case_display = str(case_key).replace("_", " ")

    seal_status = (
        "ПІДТВЕРДЖЕНО (ланцюг цілісний)" if chain_ok
        else f"ПОРУШЕНО на запису #{case_report.get('broken_at_seq')}"
    )

    story = [
        Paragraph("АКТ ОБЛІКУ ДОКАЗІВ / CHAIN OF CUSTODY", title_style),
        Paragraph(f"Справа / Case: {case_display}", small),
        Paragraph(f"Сформовано / Generated: {generated}", small),
        Paragraph(f"Кількість доказів / Evidence items: {len(rows)}", small),
        Spacer(1, 5 * mm),
        Paragraph("Перелік доказів (hash-ланцюг) / Evidence inventory", h2_style),
    ]

    # Evidence table. Hashes are rendered as wrapped Paragraphs (mono) so long
    # sha256 strings do not overflow the column.
    header = ["#", "Файл / File", "Розмір", "Хеші (MD5 / SHA1 / SHA256)",
              "Прийнято (UTC)", "Хто"]
    data = [header]
    for r in rows:
        ingested = r["ingested_at"]
        if isinstance(ingested, datetime):
            ts = ingested.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts = str(ingested)
        hashes = (
            f"MD5: {r['md5']}<br/>SHA1: {r['sha1']}<br/>SHA256: {r['sha256']}"
        )
        data.append([
            str(r["seq"]),
            Paragraph(str(r["file_name"]), mono),
            _fmt_size(int(r["size_bytes"])),
            Paragraph(hashes, mono),
            Paragraph(ts, mono),
            Paragraph(str(r.get("uploader_chat") or "—"), mono),
        ])

    table = Table(
        data,
        colWidths=[8 * mm, 34 * mm, 16 * mm, 78 * mm, 22 * mm, 24 * mm],
        repeatRows=1,
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), bold_font),
        ("FONTNAME", (0, 1), (-1, -1), font),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(table)
    story.append(Spacer(1, 6 * mm))

    # Chain seal block — the tamper-evident summary an analyst/court relies on.
    story.append(Paragraph("Печатка ланцюга / Chain seal", h2_style))
    seal_rows = [
        ["Статус цілісності / Integrity", seal_status],
        ["Алгоритм / Algorithm", "SHA-256 hash chain (per-case)"],
        ["Фінальний хеш / Final row hash", seal or "—"],
        ["Записів у ланцюзі / Rows", str(len(rows))],
        ["Перевірено / Verified at", generated],
    ]
    seal_table = Table(
        [[Paragraph(k, small), Paragraph(v, mono)] for k, v in seal_rows],
        colWidths=[55 * mm, 127 * mm],
    )
    seal_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eceff1")),
        ("FONTNAME", (0, 0), (-1, -1), font),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(seal_table)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph(
        "Цей документ згенеровано автоматично системою DFIR. Кожен запис "
        "криптографічно прив'язаний до попереднього (SHA-256). Будь-яка зміна "
        "або видалення запису порушує печатку ланцюга та виявляється під час "
        "перевірки.",
        small,
    ))

    doc.build(story)
    return buf.getvalue()


# ───────────────────────────────────────────────────────────────────────────
# Manual smoke test (run inside the container):  python -m analysis.evidence_manifest
# ───────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":  # pragma: no cover
    import sys

    logging.basicConfig(level=logging.INFO)
    ensure_schema()
    ok, rep = verify_chain()
    print("chain ok:", ok)
    for ck, info in rep["cases"].items():
        print(f"  {ck}: rows={info['rows']} ok={info['ok']} "
              f"broken_at={info['broken_at_seq']}")
    if len(sys.argv) > 1:
        pdf = build_manifest_pdf(sys.argv[1])
        if pdf:
            out = f"/tmp/coc_{sys.argv[1]}.pdf"
            with open(out, "wb") as fh:
                fh.write(pdf)
            print("wrote", out, len(pdf), "bytes")
        else:
            print("no evidence for", sys.argv[1])
