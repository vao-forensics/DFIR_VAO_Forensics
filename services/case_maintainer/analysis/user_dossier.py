# -*- coding: utf-8 -*-
"""Everything one person did, on one page, in a form you can hand to somebody.

The pieces already existed and never met: bot_users knows who they are, bot_audit_events
has what they pressed and asked (2343 button presses, 520 questions, 95 uploads at the
time of writing), upload_audit_v1 now has every file with its hash and verdict, and the
VPN map turns a tunnel address into an account name. Answering "what did this person do"
meant three queries and a memory of which table held what.

This is deliberately read-only and self-contained: no chart libraries, no external CSS,
nothing that needs the network. It renders in a browser and prints to PDF as it stands,
because the reason for wanting it is usually that something has to be proven.
"""
import html
import json


def _rows(cur, sql, args):
    cur.execute(sql, args)
    return cur.fetchall() or []


def collect(conn, user_id='', chat_id='', limit_events=200, limit_uploads=200):
    """Everything known about one person. user_id or chat_id - either will do."""
    uid = str(user_id or '').strip()
    cid = str(chat_id or '').strip()
    out = {'user_id': uid, 'chat_id': cid, 'profile': {}, 'stats': {},
           'events': [], 'uploads': [], 'cases': [], 'vpn': []}
    with conn.cursor() as cur:
        prof = _rows(cur, """
            SELECT user_id, COALESCE(username,''), COALESCE(first_name,''),
                   COALESCE(last_name,''), COALESCE(lang,''), COALESCE(role,''),
                   enabled, COALESCE(notes,'')
              FROM public.bot_users
             WHERE (%s <> '' AND user_id::text = %s)
                OR (%s <> '' AND user_id::text = %s)
             LIMIT 1""", (uid, uid, cid, cid))
        if prof:
            r = prof[0]
            out['profile'] = {'user_id': str(r[0]), 'username': r[1], 'first_name': r[2],
                              'last_name': r[3], 'lang': r[4], 'role': r[5],
                              'enabled': bool(r[6]), 'notes': r[7]}
            if not uid:
                uid = str(r[0])
                out['user_id'] = uid

        key = uid or cid
        if key:
            out['events'] = [
                {'ts': str(r[0]), 'type': r[1], 'status': r[2] or '', 'text': r[3] or ''}
                for r in _rows(cur, """
                    SELECT ts, event_type, status, query_short
                      FROM public.bot_audit_events
                     WHERE user_id::text = %s OR chat_id::text = %s
                     ORDER BY ts DESC LIMIT %s""", (key, key, limit_events))]

            counts = _rows(cur, """
                SELECT event_type, count(*),
                       count(*) FILTER (WHERE ts > now() - interval '24 hours'),
                       count(*) FILTER (WHERE ts > now() - interval '7 days')
                  FROM public.bot_audit_events
                 WHERE user_id::text = %s OR chat_id::text = %s
                 GROUP BY 1 ORDER BY 2 DESC""", (key, key))
            out['stats'] = {r[0]: {'total': int(r[1]), 'd1': int(r[2]), 'd7': int(r[3])}
                            for r in counts}

        if cid or uid:
            try:
                out['uploads'] = [
                    {'ts': str(r[0]), 'verdict': r[1], 'reason_code': r[2] or '',
                     'reason': r[3] or '', 'case_key': r[4] or '', 'mode': r[5] or '',
                     'file_name': r[6] or '', 'size': int(r[7] or 0), 'sha256': r[8] or '',
                     'vpn_ip': r[9] or '', 'vpn_client': r[10] or '',
                     'where': (r[11] or r[12] or '')}
                    for r in _rows(cur, """
                        SELECT ts, verdict, reason_code, reason, case_key, mode, file_name,
                               size_bytes, sha256, vpn_ip, vpn_client, stored_path,
                               quarantine_path
                          FROM public.upload_audit_v1
                         WHERE chat_id = %s OR chat_id = %s
                         ORDER BY ts DESC LIMIT %s""", (cid or uid, uid or cid, limit_uploads))]
            except Exception:
                out['uploads'] = []      # table appears with the first upload

        seen = []
        for u in out['uploads']:
            if u['case_key'] and u['case_key'] not in seen:
                seen.append(u['case_key'])
        out['cases'] = seen

        for u in out['uploads']:
            pair = (u['vpn_ip'], u['vpn_client'])
            if pair[0] and pair not in out['vpn']:
                out['vpn'].append(pair)
        out['vpn'] = [{'ip': a, 'client': b} for a, b in out['vpn']]
    return out


def _e(s):
    return html.escape(str(s if s is not None else ''))


def _size(n):
    n = int(n or 0)
    for unit, div in (('ГБ', 1024 ** 3), ('МБ', 1024 ** 2), ('КБ', 1024)):
        if n >= div:
            return '%.1f %s' % (n / float(div), unit)
    return '%d Б' % n


def render_html(d):
    p = d.get('profile') or {}
    title = (p.get('username') and '@' + p['username']) or p.get('first_name') or \
        d.get('user_id') or d.get('chat_id') or '?'
    st = d.get('stats') or {}
    up = d.get('uploads') or []
    rejected = [u for u in up if u['verdict'] != 'accepted']

    css = """
    body{font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif;margin:24px;color:#111;background:#fff}
    h1{font-size:20px;margin:0 0 4px} h2{font-size:15px;margin:22px 0 6px;color:#333}
    .muted{color:#666} table{border-collapse:collapse;width:100%;margin-top:6px}
    th,td{border:1px solid #ddd;padding:5px 7px;text-align:left;vertical-align:top;font-size:13px}
    th{background:#f5f5f5;font-weight:600} code{font-family:ui-monospace,Consolas,monospace;font-size:12px}
    .bad{color:#a30000;font-weight:600} .ok{color:#065f00}
    .kpi{display:inline-block;border:1px solid #ddd;border-radius:6px;padding:6px 10px;margin:4px 6px 0 0}
    .kpi b{font-size:17px;display:block}
    @media print{body{margin:0} .noprint{display:none}}
    """

    h = ['<!doctype html><meta charset="utf-8"><title>Досьє: %s</title><style>%s</style>'
         % (_e(title), css)]
    h.append('<h1>Досьє користувача: %s</h1>' % _e(title))
    h.append('<div class="muted">user_id %s · chat_id %s · роль %s · %s</div>' % (
        _e(p.get('user_id') or d.get('user_id')), _e(d.get('chat_id') or p.get('user_id')),
        _e(p.get('role') or '—'),
        '<span class="ok">увімкнений</span>' if p.get('enabled') else
        '<span class="bad">вимкнений</span>'))
    if p.get('notes'):
        h.append('<div class="muted">нотатка: %s</div>' % _e(p['notes']))

    h.append('<h2>Активність</h2>')
    for k in sorted(st, key=lambda x: -st[x]['total']):
        h.append('<span class="kpi"><b>%d</b>%s <span class="muted">(24г %d · 7д %d)</span></span>'
                 % (st[k]['total'], _e(k), st[k]['d1'], st[k]['d7']))
    if not st:
        h.append('<div class="muted">подій не знайдено</div>')

    if d.get('vpn'):
        h.append('<h2>VPN-акаунти, з яких заливав</h2><table><tr><th>адреса</th>'
                 '<th>акаунт</th></tr>')
        for v in d['vpn']:
            h.append('<tr><td><code>%s</code></td><td>%s</td></tr>'
                     % (_e(v['ip']), _e(v['client'])))
        h.append('</table>')

    h.append('<h2>Завантаження (%d, з них відхилено %d)</h2>' % (len(up), len(rejected)))
    if up:
        h.append('<table><tr><th>час</th><th>вердикт</th><th>файл</th><th>розмір</th>'
                 '<th>SHA-256</th><th>справа</th><th>акаунт VPN</th><th>причина</th></tr>')
        for u in up:
            cls = 'ok' if u['verdict'] == 'accepted' else 'bad'
            h.append('<tr><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td>'
                     '<td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                         _e(u['ts'][:19]), cls, _e(u['verdict']), _e(u['file_name']),
                         _size(u['size']), _e(u['sha256'][:24]), _e(u['case_key']),
                         _e(u['vpn_client'] or u['vpn_ip']),
                         _e(u['reason_code'] or '')))
        h.append('</table>')
    else:
        h.append('<div class="muted">завантажень не знайдено</div>')

    h.append('<h2>Останні дії (%d)</h2>' % len(d.get('events') or []))
    if d.get('events'):
        h.append('<table><tr><th>час</th><th>тип</th><th>статус</th><th>що саме</th></tr>')
        for e in d['events']:
            h.append('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' % (
                _e(e['ts'][:19]), _e(e['type']), _e(e['status']), _e(e['text'])[:300]))
        h.append('</table>')
    else:
        h.append('<div class="muted">подій не знайдено</div>')

    h.append('<h2 class="noprint">Дані</h2>'
             '<div class="noprint muted">Той самий зміст у JSON: додайте <code>&amp;format=json</code> '
             'до адреси.</div>')
    return ''.join(h)


def render_json(d):
    return json.dumps(d, ensure_ascii=False, indent=1)
