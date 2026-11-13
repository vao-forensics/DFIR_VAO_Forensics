# -*- coding: utf-8 -*-
"""Pure-Python Windows Prefetch parser (v17/23/26/30/31, MAM-compressed Win10/11 files).

Why: PECmd 1.x refused Prefetch v31 (Windows 11 24H2+) and the collector's rescue cannot run .NET on
the VM, so cases like case_08 arrived with 414 raw .pf and 0 parsed launches. Decompression
uses dissect.util (LZXPRESS Huffman); layout offsets follow the libscca documentation.

API:
  parse_prefetch(data: bytes) -> dict | None
      {'version', 'executable', 'hash', 'run_count', 'last_run' (datetime|None),
       'run_times': [datetime...] (newest first), 'files': [str...], 'volumes': [{'device','created','serial'}]}
  rows_from_prefetch(name, data) -> PECmd-compatible dict (ExecutableName, RunCount, LastRun, PreviousRun0..6,
       SourceFilename, Hash, Volume0Name, Volume0Serial, Volume0Created, FilesLoaded)
"""
import struct, datetime

_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)


def _filetime(v):
    if not v or v < 10 ** 16:
        return None
    try:
        return _EPOCH + datetime.timedelta(microseconds=v // 10)
    except Exception:
        return None


def _decompress(data):
    if data[:3] == b'MAM':
        size = struct.unpack_from('<I', data, 4)[0]
        from dissect.util.compression import lzxpress_huffman
        try:
            out = lzxpress_huffman.decompress(data[8:])
        except TypeError:
            out = lzxpress_huffman.decompress(data[8:], size)
        return bytes(out)[:size]
    return data


# version -> (file_info_size, run_times_offset, run_times_count, run_count_offset)
_LAYOUT = {
    17: (0x98, 0x24, 1, 0x3C),
    23: (0xF4, 0x2C, 1, 0x44),
    26: (0xE0, 0x2C, 8, 0x7C),
    30: (0xE0, 0x2C, 8, 0x7C),
    31: (0xE0, 0x2C, 8, 0x7C),
}


def parse_prefetch(data):
    try:
        data = _decompress(data)
    except Exception:
        return None
    if len(data) < 0x54 + 0x40 or data[4:8] != b'SCCA':
        return None
    version = struct.unpack_from('<I', data, 0)[0]
    lay = _LAYOUT.get(version)
    if not lay:
        return None
    exe = data[0x10:0x10 + 60].decode('utf-16-le', 'ignore').split('\x00', 1)[0]
    h = struct.unpack_from('<I', data, 0x4C)[0]
    fi = 0x54
    _, rt_off, rt_n, rc_off = lay
    metrics_off, metrics_n, chains_off, chains_n, fn_off, fn_size, vol_off, vol_n, vol_size = struct.unpack_from('<9I', data, fi)
    run_times = []
    for i in range(rt_n):
        v = struct.unpack_from('<Q', data, fi + rt_off + 8 * i)[0]
        t = _filetime(v)
        if t:
            run_times.append(t)
    # run count: v26/v30 at +0x7C; v31 (Win11 24H2+) at +0x74 — measured on 414 files: +0x74 carries
    # 344/369/370/2/1 and agrees with the number of stored run times, +0x7C is 3/3/3/0/0. Pick the
    # candidate that is plausible and consistent with the run-time slots.
    cands = []
    for off in ((0x74, 0x7C) if version == 31 else (rc_off, 0x74, 0x80)):
        if fi + off + 4 <= len(data):
            cands.append(struct.unpack_from('<I', data, fi + off)[0])
    n_rt = sum(1 for i in range(rt_n) if struct.unpack_from('<Q', data, fi + rt_off + 8 * i)[0] >= 10 ** 16)
    run_count = next((c for c in cands if 0 < c < 10 ** 7 and c >= n_rt), cands[0] if cands else 0)
    files = []
    if fn_off and fn_size and fn_off + fn_size <= len(data):
        blob = data[fn_off:fn_off + fn_size].decode('utf-16-le', 'ignore')
        files = [x for x in blob.split('\x00') if x]
    volumes = []
    if vol_off and vol_n and vol_off < len(data):
        entry = 0x60 if version >= 26 else 0x28
        for i in range(min(vol_n, 8)):
            base = vol_off + i * entry
            if base + 0x14 > len(data):
                break
            dn_off, dn_len, created, serial = struct.unpack_from('<IIQI', data, base)
            dev = ''
            p = vol_off + dn_off
            if 0 < dn_len < 4096 and p + dn_len * 2 <= len(data):
                dev = data[p:p + dn_len * 2].decode('utf-16-le', 'ignore').rstrip('\x00')
            volumes.append({'device': dev, 'created': _filetime(created), 'serial': '%08X' % serial})
    return {'version': version, 'executable': exe, 'hash': '%08X' % h, 'run_count': run_count,
            'last_run': run_times[0] if run_times else None, 'run_times': run_times, 'files': files, 'volumes': volumes}


def rows_from_prefetch(name, data):
    p = parse_prefetch(data)
    if not p:
        return None
    fmt = lambda t: t.strftime('%Y-%m-%d %H:%M:%S') if t else ''
    row = {'SourceFilename': name, 'ExecutableName': p['executable'], 'Hash': p['hash'], 'Version': str(p['version']),
           'RunCount': str(p['run_count']), 'LastRun': fmt(p['last_run'])}
    for i in range(7):
        row['PreviousRun%d' % i] = fmt(p['run_times'][i + 1]) if len(p['run_times']) > i + 1 else ''
    v0 = p['volumes'][0] if p['volumes'] else {}
    row['Volume0Name'] = v0.get('device', '')
    row['Volume0Serial'] = v0.get('serial', '')
    row['Volume0Created'] = fmt(v0.get('created'))
    row['FilesLoaded'] = ', '.join(p['files'][:200])
    row['Directories'] = ', '.join(sorted({f.rsplit('\\', 1)[0] for f in p['files'] if '\\' in f})[:50])
    return row


if __name__ == '__main__':
    import sys, glob, json
    for f in sys.argv[1:] or glob.glob('/data/state/truth/pf/*.pf'):
        r = rows_from_prefetch(f.rsplit('/', 1)[-1], open(f, 'rb').read())
        print(json.dumps({k: (v if len(str(v)) < 90 else str(v)[:90] + '…') for k, v in (r or {}).items() if k in ('SourceFilename', 'ExecutableName', 'Version', 'RunCount', 'LastRun', 'PreviousRun0', 'Volume0Name', 'Volume0Created')}, ensure_ascii=False) if r else 'PARSE-FAIL ' + f)
