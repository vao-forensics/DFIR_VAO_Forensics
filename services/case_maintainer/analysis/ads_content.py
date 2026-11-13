"""What sits inside an alternate data stream the collector saved (ads_streams.csv + ads/NNNN.bin).

Collector v4.9+ writes, for every non-standard named stream on the target disk, one CSV row and
up to 1 MB of its bytes. The $MFT listing gave us only the stream's name and size; this module
turns the bytes into something an analyst and the report can use: what kind of content it is,
a printable preview, and how serious it looks.

Why (23.10.2026): both notary cases carried \\ProgramData\\TEMP:<hex> on a folder and nobody
could say what was in it.
"""
import re

# names Windows, browsers, Office and sync clients write themselves (same idea as the
# collector's list and threat_detect's _ADS_OK; kept here so old/foreign archives are filtered too)
BENIGN = re.compile(r'^(wofcompresseddata|zone\.identifier|streamedfilestate|encryptable|oecustomproperty|smartscreen'
                    r'|favicon|originalpath|sec\.endpointdlp|\$.*|\{4c8cc155-6c1e-11d1-8e41-00c04fb9386d\}'
                    r'|afp_afpinfo|afp_resource|com\.dropbox\.attrs?|com\.dropbox\.attributes|ms-properties|kpmatt'
                    r'|win32app_1|taskbarpinned|mbam\.scanned|ca_inoculateit|kavichs|com\.apple\..*)$', re.I)

_SCRIPT = re.compile(r'(iex\b|invoke-expression|downloadstring|frombase64string|new-object\s+net\.webclient'
                     r'|powershell|wscript\.shell|createobject|cmd(\.exe)?\s*/c|rundll32|regsvr32|mshta'
                     r'|certutil|bitsadmin|<script|eval\(|function\s*\(|#!/)', re.I)
_URL = re.compile(r'https?://[^\s"\'<>]{4,}', re.I)
_B64 = re.compile(r'[A-Za-z0-9+/]{200,}={0,2}')

KIND_LABEL = {
    'pe': 'виконуваний файл Windows (MZ/PE)',
    'script': 'сценарій або команди',
    'archive': 'архів (zip/rar/7z/gzip/cab)',
    'base64': 'довгий base64 (закодований вміст)',
    'url': 'текст з адресами в інтернеті',
    'text': 'текст',
    'empty': 'порожній',
    'binary': 'двійкові дані (ключ, конфіг або зашифрований вміст)',
}


def kind(data):
    """Content class of the stream bytes."""
    if not data:
        return 'empty'
    if data[:2] == b'MZ':
        return 'pe'
    if data[:4] in (b'PK\x03\x04', b'Rar!', b'7z\xbc\xaf') or data[:2] == b'\x1f\x8b' or data[:4] == b'MSCF':
        return 'archive'
    txt = text_of(data)
    if txt is None:
        return 'binary'
    if _SCRIPT.search(txt):
        return 'script'
    if _B64.search(txt):
        return 'base64'
    if _URL.search(txt):
        return 'url'
    return 'text'


def text_of(data):
    """Decoded text, or None for binary content. UTF-16 (BOM or every 2nd byte zero) included."""
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            return data.decode('utf-16')
        except Exception:
            return None
    sample = data[:4096]
    if len(sample) > 8 and sample[1::2].count(0) > len(sample) // 4:
        try:
            return data.decode('utf-16-le')
        except Exception:
            return None
    bad = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    if bad > max(2, len(sample) // 50):
        return None
    for enc in ('utf-8', 'cp1251'):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return None


def preview(data, n=300):
    """First n printable characters; hex of the first 32 bytes for binary content."""
    t = text_of(data or b'')
    if t is None:
        return 'hex: ' + (data or b'')[:32].hex()
    t = re.sub(r'\s+', ' ', t).strip()
    return t[:n] + ('…' if len(t) > n else '')


def severity(k, name, is_folder, size=0):
    """high = executable/script/archive/encoded payload, or a hex-named stream on a folder (the
    notary pattern), or more than 1 MB hidden; medium = anything else non-standard."""
    if k in ('pe', 'script', 'archive', 'base64') or size > 1048576:
        return 'high'
    if is_folder and re.match(r'^[0-9a-f]{6,16}$', name or '', re.I):
        return 'high'
    if re.search(r'\.(exe|dll|scr|ps1|vbs|js|jse|hta|bat|cmd|lnk)$', name or '', re.I):
        return 'high'
    return 'medium'


def analyse(rows, read_bin):
    """rows: dicts from ads_streams.csv; read_bin(rel) -> bytes or None.
    Returns enriched dicts for the non-benign streams, most serious first."""
    out = []
    for r in rows:
        name = (r.get('Stream') or '').strip()
        if not name or BENIGN.match(name):
            continue
        data = None
        if (r.get('SavedAs') or '').strip():
            try:
                data = read_bin(r['SavedAs'].strip())
            except Exception:
                data = None
        is_folder = str(r.get('IsFolder') or '').strip() == '1'
        k = kind(data) if data is not None else 'not_saved'
        size = int(r['Size']) if str(r.get('Size') or '').isdigit() else 0
        out.append({
            'path': (r.get('Path') or '').strip(), 'stream': name,
            'size': size,
            'is_folder': is_folder, 'sha256': (r.get('SHA256') or '').strip().lower(),
            'kind': k, 'kind_label': KIND_LABEL.get(k, 'вміст не збережено (більше 1 МБ)'),
            'preview': (('hex: ' + data[:32].hex()) if k in ('pe', 'archive', 'binary') else preview(data))
                       if data is not None else (r.get('Head') or '')[:120],
            'severity': severity(k, name, is_folder, size),
            'urls': sorted(set(_URL.findall(text_of(data) or '')))[:10] if data else [],
        })
    out.sort(key=lambda x: (x['severity'] != 'high', x['path']))
    return out
