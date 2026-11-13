# -*- coding: utf-8 -*-
"""Build ONE PowerShell script out of the six the collector still runs.

Why: each script is fed to powershell.exe over stdin, so today a collection starts six
separate PowerShell processes and writes six distinct script texts into the victim's log as
EID 4104 script-block records. That is six times the noise we leave behind, on a machine we
are supposed to disturb as little as possible.

The combined file runs all six inside ONE process, so the log gets one process start and
one script text — carrying one marker banner that names us.

Method: each original is wrapped verbatim in a function, its own `param(...)` block becoming
the function's parameters. The bodies are not rewritten — they are well-tuned and were
calibrated against real machines — so behaviour is unchanged. A dispatcher at the end runs
the steps in the order Steps.cs used, honouring the same output paths, and prints the same
progress tokens the C# side already parses (DIRS/FILES/DEL, TOTAL, HASHED/MB, CONT/ARCH/
DOC/TOOL, PROC/CONN/PIPE).
"""
import io
import os
import re

DIR = r"C:\DFIR\Modules\!DFIRbot"
OUT = os.path.join(DIR, "vao_collect_all.ps1")
TOKEN = "VAO_DFIR_COLLECTOR_MARKER"

STEPS = [
    ('build_fs_tree.ps1', 'Invoke-VaoFsTree'),
    ('find_suspicious.ps1', 'Invoke-VaoSuspicious'),
    ('hash_targets.ps1', 'Invoke-VaoHashes'),
    ('hunt_encrypted.ps1', 'Invoke-VaoEncrypted'),
    ('collect_motw.ps1', 'Invoke-VaoMotw'),
    ('collect_liveresponse.ps1', 'Invoke-VaoLiveResponse'),
]

BANNER = """# ==============================================================================
#  {token}
#  FORENSIC COLLECTION TOOL - NOT MALWARE.
#  TSE INSTRUMENT KRYMINALISTYCHNOHO ZBORU, A NE SHKIDLYVE PZ.
#
#  script    : vao_collect_all.ps1  (ALL PowerShell steps in ONE process)
#  collector : VAO DFIR Collector v4.5
#  purpose   : file tree, suspicious files, hashes, encrypted files, MOTW,
#              live response - all READ-ONLY collection
#  operator  : launched by a forensic examiner during evidence collection
#
#  This single file replaces six separate scripts on purpose: one PowerShell
#  process and one script-block record instead of six, so the machine under
#  examination is disturbed as little as possible.
#
#  If you are reading this inside an event log record (EID 4104), it was left
#  by OUR collector. It is the expected footprint of an examiner at work,
#  not the action of an intruder.
#  Machine-detectable token: {token}
# ==============================================================================

""".format(token=TOKEN)


def split_param_block(text):
    """Return (param_body, rest) with the leading banner+param() removed."""
    m = re.search(r'^param\s*\(', text, re.M)
    if not m:
        return None, text
    start = m.end() - 1               # at '('
    depth = 0
    for i in range(start, len(text)):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[start + 1:i], text[i + 1:]
    return None, text


parts = [BANNER]
# Its own param() block, so Ps.Run passes values exactly the way it does for the six
# separate scripts today - no change needed on the C# side beyond calling one file.
parts.append("""param(
    [string]$CsvDir = "",
    [string]$OutDir = "",
    [string]$Drive  = "C",
    [int]$Live      = 0,
    [int]$Fast      = 0
)

""")
parts.append("$ErrorActionPreference = 'Continue'\n\n")

for fn, func in STEPS:
    raw = io.open(os.path.join(DIR, fn), encoding='utf-8', errors='replace').read()
    # drop our banner comment lines; they are re-stated once at the top of this file
    body_lines = [l for l in raw.splitlines()
                  if not (l.startswith('#') and (TOKEN in l or 'FORENSIC COLLECTION' in l
                                                 or 'TSE INSTRUMENT' in l or l.strip() == '#'
                                                 or l.startswith('# ====')
                                                 or re.match(r'#\s+(script|collector|purpose|operator)\s+:', l)
                                                 or 'event log record' in l
                                                 or 'Machine-detectable token' in l
                                                 or 'by OUR collector' in l
                                                 or 'not the action of an intruder' in l))]
    raw = '\n'.join(body_lines)
    pblock, rest = split_param_block(raw)
    if pblock is None:
        raise SystemExit('no param() in %s' % fn)

    # A body that used $script:X at top level relied on script scope being its OWN scope.
    # Inside a function that stops being true: the helper writes $script:X while the body
    # reads a function-local $X, so the counters came back as zeros while the files were
    # written correctly. Promote every such variable so both sides mean the same thing.
    scoped = set(re.findall(r'\$script:([A-Za-z_][A-Za-z0-9_]*)', rest))
    for var in scoped:
        rest = re.sub(r'(?<!:)\$' + var + r'\b', '$script:' + var, rest)
        rest = rest.replace('$script:script:' + var, '$script:' + var)
    if scoped:
        print('   %-26s підвищено до script-скоупу: %s' % (fn, ', '.join(sorted(scoped))))

    # `exit` ends the PROCESS. In six separate processes that was a harmless "nothing to
    # do" path; in one shared process the first such exit kills every remaining step —
    # which is exactly what happened on the first full run: fs_tree found no MFT csv,
    # called exit 0, and the other five steps never ran. Inside a function `return` has
    # the meaning the original author intended.
    # They appear both at line start and inline, e.g.
    #     if (-not $csv) { 'DIRS|0'; 'FILES|0'; 'OUT|'; exit 0 }
    # so match the statement wherever it stands: after a line break, a semicolon or a
    # brace. Anchoring to line start only (my first attempt) left every inline one behind
    # and the run still died after the first step.
    pat = re.compile(r'(?<=[\n;{])(\s*)exit\b[ \t]*\d*')
    n_exit = len(pat.findall(rest))
    rest = pat.sub(lambda m: m.group(1) + 'return', rest)
    if n_exit:
        print('   %-26s exit -> return: %d' % (fn, n_exit))
    parts.append('# ---------------- %s ----------------\n' % fn)
    parts.append('function %s {\n' % func)
    parts.append('param(%s)\n' % pblock)
    parts.append(rest.strip('\n'))
    parts.append('\n}\n\n')

DISPATCH = """
# ------------------------------ dispatcher ------------------------------------
# Same order and the same output paths Steps.cs used when these were six files.
param() # placeholder replaced below
"""

# real dispatcher, parameterised the way the C# side calls it
parts.append("""# ------------------------------ dispatcher ------------------------------------
# One process, the same order and outputs the six separate scripts had.
# Guarded on purpose: dot-sourcing this file must only DEFINE the functions. Without the
# guard a dot-source runs every step with empty parameters, each step hits its own
# "no OutDir" early exit, and the caller sees a row of zeros - which is exactly what
# happened the first time this was tested.
if (-not $OutDir) { return }

# parameters come from the param() block above


$IsLive = [bool]$Live

Write-Output "VAO_STEP fs_tree"
Invoke-VaoFsTree -CsvDir $CsvDir -OutFile (Join-Path $OutDir 'filesystem_tree.txt')

Write-Output "VAO_STEP suspicious"
Invoke-VaoSuspicious -CsvDir $CsvDir -OutFile (Join-Path $OutDir 'suspicious_files.txt') `
                     -OutCsv (Join-Path $OutDir 'suspicious_files.csv')

# FAST profile skips the two DISK-scanning passes (hashing every flagged file, and the
# up-to-4-minute encrypted-file sweep). The tree + suspicious list are built from the MFT
# CSV that KAPE already produced, so they stay in fast mode; the disk sweeps are what made
# "fast" slow. The FULL profile still runs everything.
if ($Fast) {
    Write-Output "VAO_STEP hashes_skipped_fast"
    Write-Output "VAO_STEP encrypted_skipped_fast"
} else {
    Write-Output "VAO_STEP hashes"
    Invoke-VaoHashes -SuspectCsv (Join-Path $OutDir 'suspicious_files.csv') -Drive $Drive `
                     -OutCsv (Join-Path $OutDir 'hashes.csv')

    Write-Output "VAO_STEP encrypted"
    Invoke-VaoEncrypted -Drive $Drive -OutCsv (Join-Path $OutDir 'encrypted_files.csv') -MaxSeconds 240
}

Write-Output "VAO_STEP motw"
Invoke-VaoMotw -Drive $Drive -OutDir (Join-Path $OutDir 'motw')

if ($IsLive) {
    Write-Output "VAO_STEP liveresponse"
    Invoke-VaoLiveResponse -OutDir (Join-Path $OutDir 'live\\system')
}
Write-Output "VAO_STEP done"
""")

text = ''.join(parts)
non_ascii = [c for c in text if ord(c) > 127]
io.open(OUT, 'w', encoding='ascii', errors='replace', newline='\r\n').write(text)
print('створено: %s' % OUT)
print('розмір: %d символів, не-ASCII: %d' % (len(text), len(non_ascii)))
