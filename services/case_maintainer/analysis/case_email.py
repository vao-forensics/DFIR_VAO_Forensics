"""E-mail evidence uploaded into a case (EML / MSG, or a ZIP of them).

2026-10-08 (owner): e-mail analysis belongs to the case, like RAM and logs, not to a
stand-alone tool. The case menu offers «📧 Пошта (EML/MSG)»; the upload arrives with
mode=email and lands here. Each message is parsed with the same parsers the old tool used
(case_maintainer_addtools._parse_eml/_parse_msg), checked for the usual phishing signs and
stored in raw_fallback_v2 (parser_family='email_upload'), the same way RAM findings are, so
the report renders a section from it and nothing else has to know about a new table.

Attachments are hashed and kept next to the upload for the examiner; they are never opened
or executed here.
"""
import hashlib
import json
import logging
import os
import re
import zipfile
from email.utils import getaddresses, parseaddr

import psycopg2

from core.config import PG_DSN

_log = logging.getLogger('app')
FAMILY = 'email_upload'
MAX_MESSAGES = 500
MAX_ZIP_MEMBER = 50 * 1024 * 1024

_EXEC_EXT = {'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
             'hta', 'lnk', 'msi', 'msp', 'dll', 'cpl', 'jar', 'reg', 'iso', 'img', 'vhd', 'vhdx', 'one',
             'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'xll', 'chm', 'appref-ms', 'url', 'library-ms'}
_MEDIUM_EXT = {'zip', 'rar', '7z', 'cab', 'ace', 'gz', 'tar', 'html', 'htm', 'svg', 'shtml', 'xhtml',
               'doc', 'xls', 'ppt', 'rtf', 'pdf'}
_SHORTENERS = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'ow.ly',
               'shorturl.at', 'tiny.cc', 'clck.ru', 'u.to'}


def _domain(addr):
    a = parseaddr(addr or '')[1].lower()
    return a.split('@', 1)[1].strip('> ') if '@' in a else ''


def _url_host(u):
    m = re.match(r'https?://([^/:?#]+)', u or '', re.I)
    return (m.group(1).lower() if m else '')


def _origin_ip(received):
    """Sender-side IP: the last public [a.b.c.d] in the Received chain (the first hop)."""
    for r in reversed(received or []):
        for ip in re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', r):
            p = [int(x) for x in ip.split('.')]
            private = (p[0] == 10 or p[0] == 127 or (p[0] == 172 and 16 <= p[1] <= 31)
                       or (p[0] == 192 and p[1] == 168) or (p[0] == 169 and p[1] == 254))
            if not private:
                return ip
    return ''


def _auth_verdicts(text):
    t = (text or '').lower()
    out = {}
    for k in ('spf', 'dkim', 'dmarc'):
        m = re.search(k + r'\s*=\s*([a-z]+)', t)
        if m:
            out[k] = m.group(1)
    return out


def _analyse_one(name, parsed):
    """parsed = (summary_text, attachments[(fn, bytes)], meta, html, text)."""
    _summary, atts, meta, html_body, text_body = parsed
    meta = meta or {}
    findings = []
    frm_dom = _domain(meta.get('from'))
    rp_dom = _domain(meta.get('return_path'))
    rt_dom = _domain(meta.get('reply_to'))
    if frm_dom and rp_dom and rp_dom != frm_dom and not rp_dom.endswith('.' + frm_dom):
        findings.append(('medium', 'Return-Path (%s) не збігається з відправником (%s)' % (rp_dom, frm_dom)))
    if frm_dom and rt_dom and rt_dom != frm_dom:
        findings.append(('medium', 'Reply-To веде на інший домен (%s), ніж відправник (%s)' % (rt_dom, frm_dom)))
    auth = _auth_verdicts((meta.get('auth_results') or '') + ' ' + (meta.get('received_spf') or ''))
    for k, v in auth.items():
        if v in ('fail', 'softfail', 'permerror'):
            findings.append(('high' if v == 'fail' else 'medium', '%s=%s — автентифікація відправника не пройдена' % (k.upper(), v)))
    att_rows = []
    for fn, data in atts or []:
        fn = str(fn or 'attachment.bin')
        data = data or b''
        ext = fn.lower().rsplit('.', 1)[-1] if '.' in fn else ''
        parts = fn.lower().split('.')
        sev = 'high' if ext in _EXEC_EXT else ('medium' if ext in _MEDIUM_EXT else '')
        if len(parts) >= 3 and parts[-2] in ('pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt') and ext in _EXEC_EXT:
            findings.append(('high', 'Подвійне розширення у вкладенні: %s' % fn))
        if sev == 'high':
            findings.append(('high', 'Небезпечне вкладення: %s (.%s)' % (fn, ext)))
        elif sev == 'medium' and ext in ('zip', 'rar', '7z', 'html', 'htm', 'svg', 'iso'):
            findings.append(('medium', 'Вкладення, що часто несе шкідливе ПЗ: %s' % fn))
        att_rows.append({'name': fn, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                         'md5': hashlib.md5(data).hexdigest(), 'ext': ext, 'risk': sev or 'low'})
    links = list(dict.fromkeys(meta.get('links') or []))[:60]
    hosts = sorted({_url_host(u) for u in links if _url_host(u)})
    for u in links:
        h = _url_host(u)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', h):
            findings.append(('high', 'Посилання на IP-адресу: %s' % u[:120]))
        elif h in _SHORTENERS:
            findings.append(('medium', 'Скорочене посилання (ховає справжню адресу): %s' % u[:120]))
    rec = meta.get('received') or []
    return {
        'file': name,
        'from': meta.get('from') or '', 'to': meta.get('to') or '',
        'subject': meta.get('subject') or '', 'date': str(meta.get('date') or ''),
        'message_id': meta.get('message_id') or '', 'reply_to': meta.get('reply_to') or '',
        'return_path': meta.get('return_path') or '', 'x_mailer': meta.get('x_mailer') or '',
        'auth': auth, 'origin_ip': _origin_ip(rec), 'received_hops': len(rec),
        'attachments': att_rows, 'links': links, 'link_hosts': hosts,
        'body_excerpt': (text_body or re.sub(r'<[^>]+>', ' ', html_body or ''))[:1500],
        'findings': [{'severity': s, 'why': w} for s, w in findings],
        'severity': 'high' if any(s == 'high' for s, _ in findings) else ('medium' if findings else 'low'),
    }


def _iter_messages(path, workdir):
    """Yield (display_name, local_path) for every EML/MSG in the upload."""
    low = path.lower()
    if low.endswith(('.eml', '.msg')):
        yield os.path.basename(path), path
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            n = 0
            for info in z.infolist():
                if info.is_dir() or not info.filename.lower().endswith(('.eml', '.msg')):
                    continue
                if info.file_size > MAX_ZIP_MEMBER:
                    continue
                n += 1
                if n > MAX_MESSAGES:
                    break
                safe = re.sub(r'[^\w.\-]+', '_', os.path.basename(info.filename))[:120] or ('msg%d.eml' % n)
                dst = os.path.join(workdir, '%04d_%s' % (n, safe))
                with z.open(info) as src, open(dst, 'wb') as out:
                    out.write(src.read())
                yield info.filename, dst


def ingest(case_key, upload_path):
    """Parse the upload, store one row per message, return a summary dict."""
    from case_maintainer_addtools import _parse_eml, _parse_msg
    base = os.path.dirname(upload_path)
    workdir = os.path.join(base, '_extract_' + hashlib.sha256(upload_path.encode()).hexdigest()[:10])
    attdir = os.path.join(base, 'attachments')
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(attdir, exist_ok=True)
    results, errors = [], []
    for disp, p in _iter_messages(upload_path, workdir):
        try:
            parsed = _parse_msg(p) if p.lower().endswith('.msg') else _parse_eml(p)
            r = _analyse_one(disp, parsed)
            for fn, data in parsed[1] or []:
                h = hashlib.sha256(data or b'').hexdigest()
                ap = os.path.join(attdir, h + '.bin')
                if not os.path.exists(ap):
                    with open(ap, 'wb') as fh:
                        fh.write(data or b'')
            results.append(r)
        except Exception as e:
            errors.append('%s: %s' % (disp, repr(e)[:120]))
    try:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    except Exception:
        pass
    if results:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                for r in results:
                    cur.execute("INSERT INTO raw_fallback_v2 (case_key, parser_family, source_file, payload) "
                                "VALUES (%s,%s,%s,%s)",
                                (case_key, FAMILY, os.path.basename(upload_path) + ':' + r['file'][:200],
                                 json.dumps(r, ensure_ascii=False)))
    return {'messages': len(results), 'errors': errors,
            'high': sum(1 for r in results if r['severity'] == 'high'),
            'medium': sum(1 for r in results if r['severity'] == 'medium'),
            'results': results}


def summary_text(case_key, res):
    lines = ['📧 Пошту додано до справи %s' % case_key.replace('_', ' '),
             'Листів розібрано: %d · підозрілих: %d високий, %d середній' % (res['messages'], res['high'], res['medium'])]
    for r in [x for x in res['results'] if x['severity'] != 'low'][:8]:
        lines.append('')
        lines.append('• %s — «%s»' % ((r['from'] or '?')[:60], (r['subject'] or '')[:80]))
        for f in r['findings'][:4]:
            lines.append('   %s %s' % ('🔴' if f['severity'] == 'high' else '🟠', f['why'][:150]))
    if res['errors']:
        lines.append('')
        lines.append('Не вдалося прочитати: %d файл(ів)' % len(res['errors']))
    if not res['messages']:
        lines.append('У файлі не знайдено листів .eml / .msg.')
    lines.append('')
    lines.append('Розділ «Пошта» з\'явиться у звіті при наступному DFIR-аналізі справи.')
    return '\n'.join(lines)


def render_section(case_key):
    """Markdown lines for the report, or [] when the case has no uploaded e-mail."""
    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT payload FROM raw_fallback_v2 WHERE case_key=%s AND parser_family=%s "
                            "ORDER BY row_id LIMIT %s", (case_key, FAMILY, MAX_MESSAGES))
                rows = [r[0] if isinstance(r[0], dict) else json.loads(r[0]) for r in cur.fetchall() or []]
    except Exception:
        return []
    if not rows:
        return []
    order = {'high': 0, 'medium': 1, 'low': 2}
    rows.sort(key=lambda r: order.get(r.get('severity'), 3))
    out = ['', '## 📧 ПОШТА (завантажені листи EML/MSG)',
           '_Листи додано до справи окремо; висновки нижче — з їхніх заголовків, вкладень і посилань._',
           '', 'Листів: %d · підозрілих: %d' % (len(rows), sum(1 for r in rows if r.get('severity') != 'low')), '']
    for r in rows[:25]:
        mark = {'high': '🔴', 'medium': '🟠'}.get(r.get('severity'), '⚪')
        out.append('%s **%s** — від `%s` до `%s`, %s' % (mark, (r.get('subject') or '(без теми)')[:100],
                   (r.get('from') or '?')[:80], (r.get('to') or '?')[:80], (r.get('date') or '')[:40]))
        if r.get('origin_ip'):
            out.append('   - IP відправника (перший вузол Received): `%s`' % r['origin_ip'])
        if r.get('auth'):
            out.append('   - Автентифікація: ' + ', '.join('%s=%s' % (k.upper(), v) for k, v in r['auth'].items()))
        for f in (r.get('findings') or [])[:6]:
            out.append('   - %s' % f.get('why', '')[:200])
        for a in (r.get('attachments') or [])[:6]:
            out.append('   - Вкладення `%s` (%d байт) SHA256 `%s`' % (a['name'][:80], a['size'], a['sha256']))
        if r.get('link_hosts'):
            out.append('   - Домени посилань: ' + ', '.join('`%s`' % h for h in r['link_hosts'][:10]))
        out.append('')
    return out
