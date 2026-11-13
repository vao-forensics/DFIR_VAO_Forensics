"""Triage of Autorunsc output — persistence entry points.

METHOD (Study Course lab, adapted and automated)
    Stage 1 — cut the volume: keep only entries that are ENABLED and whose signature is not
    trusted, i.e. «(Not verified)», blank («simple entries» — no publisher, no signature), or
    a publisher that is not a recognised major vendor. Trusted major-vendor signatures are
    dropped. This can in principle hide a signed-malware case, but stolen certificates from
    Microsoft/Apple/Google are rare enough that this is the accepted first cut.

    Stage 2 — rank what survives, using signals the lab applies by hand:
      * image path in C:\\Windows or C:\\Windows\\System32 — folders malware favours for
        credibility (but which also hold thousands of legitimate files);
      * the file is NOT in a vanilla Windows baseline (VanillaWindowsReference index) —
        the strongest single signal, and the reason that index was built;
      * a script (.bat/.cmd/.ps1/.vbs/.js) used as a persistence payload;
      * a base64 blob in the launch string (powershell -enc …) — obfuscated command;
      * KnownDLLs entry whose file is not in the baseline — DLL load-order hijack;
      * «File not found» → DE-prioritised: the entry is stale, not active.

    Nothing is deleted; low-ranked items are kept in a review bucket, the same principle used
    by the MFT suspicious-file pass.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3

HASHDB_DIR = os.environ.get("DFIR_HASHDB_DIR", "/data/case_library/_hashdb")
VANILLA = os.path.join(HASHDB_DIR, "vanilla_paths.sqlite")

# Recognised major vendors whose valid signature is accepted as trust.
TRUSTED = re.compile(
    r"(microsoft|windows|google|apple|adobe|intel|nvidia|amd\b|realtek|oracle|mozilla|"
    r"dell|hewlett|lenovo|vmware|citrix|cisco|symantec|mcafee|eset|kaspersky|avast|"
    r"bitdefender|dropbox|zoom|logitech|synaptics|qualcomm|broadcom)", re.I)
NOT_VERIFIED = re.compile(r"\(not verified\)", re.I)

SCRIPT_EXT = re.compile(r"\.(bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta)(\s|$|\")", re.I)
WIN_DIR = re.compile(r"^[a-z]:\\windows(\\system32|\\syswow64)?\\[^\\]+$", re.I)
# a long base64 run, typically after -enc / -EncodedCommand
B64 = re.compile(r"(?:-e(?:nc|ncodedcommand)?\s+)?([A-Za-z0-9+/]{40,}={0,2})", re.I)
# Servicing / component stores hold GENUINE Microsoft binaries on paths the vanilla
# index does not carry (it is built from installed clean images, not from every
# side-by-side variant). Excluded from the masquerade rule so that real Windows
# files are not called masquerades.
SERVICING_DIR = re.compile(
    r"\\windows\\(winsxs|servicing|softwaredistribution|assembly|"
    r"system32\\driverstore|syswow64\\driverstore)\\", re.I)


def _fp(s):
    return hashlib.blake2b(s.lower().encode("utf-8", "replace"), digest_size=8).digest()


class Baseline:
    """VanillaWindowsReference membership: does this path/name exist in a stock Windows?"""

    def __init__(self, path=VANILLA):
        self.con = None
        if os.path.exists(path):
            try:
                self.con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
            except sqlite3.Error:
                self.con = None

    @property
    def available(self):
        return self.con is not None

    def _has(self, table, value):
        if not self.con:
            return None            # unknown, not False - never claim a check that did not run
        try:
            r = self.con.execute("SELECT 1 FROM %s WHERE fp=?" % table, (_fp(value),)).fetchone()
            return r is not None
        except sqlite3.Error:
            return None

    def path_known(self, full_path):
        p = (full_path or "").strip().strip('"')
        if not p or "\\" not in p:
            return None
        d, n = p.rsplit("\\", 1)
        return self._has("vpath", d + "\\" + n)

    def name_known(self, full_path):
        p = (full_path or "").strip().strip('"')
        if not p:
            return None
        n = p.rsplit("\\", 1)[-1]
        return self._has("vname", n)


def _col(row, *names):
    for n in names:
        for k in row:
            if k and k.strip().lower() == n.lower():
                return (row.get(k) or "").strip()
    return ""


def is_untrusted(signer):
    s = (signer or "").strip()
    if not s:
        return True, "без цифрового підпису"
    if NOT_VERIFIED.search(s):
        return True, "підпис не перевірено"
    if not TRUSTED.search(s):
        return True, "видавець не є відомим великим постачальником"
    return False, ""


def triage(rows, baseline=None):
    """Returns {'high': [...], 'review': [...], 'checked': n, 'baseline': bool}."""
    bl = baseline if baseline is not None else Baseline()
    high, review = [], []
    checked = 0

    for row in rows or []:
        enabled = _col(row, "Enabled")
        if enabled and enabled.strip().lower() != "enabled":
            continue                       # only active entry points
        signer = _col(row, "Signer")
        untrusted, why = is_untrusted(signer)
        if not untrusted:
            continue                       # trusted major vendor - dropped by design
        checked += 1

        category = _col(row, "Category")
        entry = _col(row, "Entry")
        loc = _col(row, "Entry Location")
        img = _col(row, "Image Path")
        launch = _col(row, "Launch String")
        sha256 = _col(row, "SHA-256", "SHA256")

        reasons = [why]
        score = 1
        stale = "file not found" in img.lower() or "file not found" in launch.lower()

        if img and WIN_DIR.match(img.strip().strip('"')):
            score += 1
            reasons.append("розташування у системній теці Windows")

        known_path = bl.path_known(img) if img else None
        if known_path is False:
            score += 2
            reasons.append("файла немає у штатній збірці Windows")
            # T1036 masquerading. "not in the baseline" is the same +2 for an ordinary
            # third-party utility and for `svchost.exe` living under AppData — yet only
            # the second one is an attack. The NAME index (built alongside vpath, and the
            # reason Baseline.name_known exists) separates them; it had no caller, so the
            # autostart section could not tell the two apart. Raises suspicion only —
            # never lowers it, so a stock name can hide nothing.
            try:
                if not SERVICING_DIR.search(img or "") and bl.name_known(img) is True:
                    score += 2
                    reasons.append("імʼя файлу штатне для Windows, а шлях — ні "
                                   "(ознака маскараду, MITRE T1036)")
            except Exception:
                pass
        elif known_path is True:
            reasons.append("шлях відповідає штатній Windows")

        if SCRIPT_EXT.search(img or "") or SCRIPT_EXT.search(launch or ""):
            score += 1
            reasons.append("як механізм закріплення використано скрипт")

        m = B64.search(launch or "")
        if m and len(m.group(1)) >= 40:
            score += 2
            reasons.append("у рядку запуску закодована base64-команда")

        if category.lower().startswith("knowndll") and known_path is False:
            score += 2
            reasons.append("KnownDLLs вказує на файл поза штатною збіркою — можливе перехоплення завантаження DLL")

        if stale:
            score -= 2
            reasons.append("файл відсутній на диску — запис неактивний")

        item = {"category": category, "entry": entry, "location": loc,
                "image_path": img, "launch": launch[:300], "signer": signer,
                "sha256": sha256, "score": score, "reasons": reasons}
        (high if score >= 3 else review).append(item)

    high.sort(key=lambda x: -x["score"])
    return {"high": high, "review": review, "checked": checked,
            "baseline": bl.available}
