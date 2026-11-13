# -*- coding: utf-8 -*-
"""Compare, per approved case: verified truth / analyst reference -> deterministic layer -> LLM final
conclusion. Reads the LLM baseline reports (state/truth/llm_baseline/<case>.txt), the truth file and
the analyst references; checks the DB for every concrete artefact the LLM names.
Output: /data/state/truth/llm_compare/<stamp>.md (table) + .json (details). No LLM calls.

Columns: case | ключові факти | LLM знайшла | пропустила | вигадала | неправильна атрибуція | результат
"""
import sys, io, os, re, json, glob, datetime
sys.path.insert(0, '/app')
import psycopg2
from core.config import PG_DSN

BASE = '/data/state/truth/llm_120b'
OUTD = '/data/state/truth/llm_compare_120b'
TRUTH = '/app/analysis/truth/cases.json'
ANALYST = '/data/state/truth/analyst'
OWN_RX = re.compile(r'(kape|dfirtriage|dfir_collector|dfp_|vao_|7za|dumpit|ftkimager|magnet|autoruns|procexp|cports|gkape|winpmem|belkasoft|evtxecmd|pecmd|mftecmd|recmd|hayabusa|thor|loki|deepblue)', re.I)
GENERIC_EXE = {'explorer.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe', 'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'wscript.exe',
               'cscript.exe', 'conhost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'msiexec.exe', 'taskhostw.exe', 'wmic.exe',
               'certutil.exe', 'bitsadmin.exe', 'schtasks.exe', 'net.exe', 'net1.exe', 'reg.exe', 'sc.exe', 'whoami.exe', 'ntdsutil.exe'}
INTRUSION_RX = re.compile(r'скомпромет|атак[аиу]|зловмисник|шкідлив|троян|бекдор|ransom|шифруван|wiper|тунел|ngrok|rat\b|віддален[а-я]+ доступ', re.I)
CALM_RX = re.compile(r'ознак атаки[^.]{0,40}не (знайдено|виявлено)|стороннього втручання не виявлено|критичних[^.]{0,30}не виявлено', re.I)
ATTACK_CLAIM_RX = re.compile(r'атака почалася|зловмисник (отримав|закріпився|встановив|запустив)|скомпрометован', re.I)


# A claim only counts when the sentence carrying it is not a denial. Checking a fixed window of
# characters missed «неможливо ... скомпрометована» (single word, far from the match), which is the
# most common way a careful model says the opposite of a compromise claim.
DENY_RX = re.compile(r'неможлив|не можна|не вдало|не вдає|не виявлен|не встановлен|не підтвердж|'
                     r'не доведен|не знайден|бракує доказ|недостатньо доказ|жодних ознак|'
                     r'без ознак|немає ознак|не\s+(?:було|є|можу|можемо)|not\s+', re.I)
_SENT_SPLIT_RX = re.compile(r'(?<=[.!?])\s+|\n')


def _claim_is_denied(text, match):
    """True when the sentence around `match` denies the claim (so it must not be counted)."""
    start = 0
    for m in _SENT_SPLIT_RX.finditer(text, 0, match.start()):
        start = m.end()
    end = len(text)
    m2 = _SENT_SPLIT_RX.search(text, match.end())
    if m2:
        end = m2.start()
    sentence = text[start:end]
    before = text[start:match.start()]
    # denial in the same sentence before the claim, or the sentence opens with one
    return bool(DENY_RX.search(before)) or bool(DENY_RX.search(sentence[:40]))


def llm_part(txt):
    """The model-written part: from the raw narrative header onward (fallback: section 7 onward)."""
    for mark in ('# FORENSIC ЗВІТ', '## 7.'):
        i = txt.find(mark)
        if i > 0:
            return txt[i:]
    return txt


def page1(txt):
    i = txt.find('## 7.')
    return txt[:i] if i > 0 else txt


def candidates(text):
    ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
    doms = set(m.lower() for m in re.findall(r'\b(?:[a-z0-9-]+\.)+(?:com|net|org|ua|ru|io|dev|info|biz|gov\.ua|edu|cc|xyz|top|online|site)\b', text, re.I))
    exes = set(m.lower() for m in re.findall(r'\b[\w\-\.]{3,60}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)\b', text, re.I))
    ips = {i for i in ips if not i.startswith(('127.', '0.', '255.'))}
    doms = {d for d in doms if not re.match(r'^(www\.)?(microsoft|windows|google|mozilla|adobe|apple|github|python|docs)\.', d)}
    exes = {e for e in exes if e not in GENERIC_EXE and not OWN_RX.search(e)}
    return sorted(ips)[:15], sorted(doms)[:15], sorted(exes)[:30]


def _loose(token):
    """A looser probe: exe/script stem without version digits; domain without the leftmost label."""
    t = token.lower()
    m = re.match(r'^(.*?)\.(exe|dll|ps1|bat|cmd|vbs|js|hta|msi|scr)$', t)
    if m:
        stem = re.sub(r'[\d._\-]+$', '', m.group(1))
        return stem[:24] if len(stem) >= 4 else t
    if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', t) and t.count('.') >= 2:
        return t.split('.', 1)[1]
    return t


SOFT_IOC = ('report_llm', 'qa_analysis', 'timeline_analysis', 'ps_c2')


def in_db(cur, ck, token):
    try:
        from analysis.output_guardrails import artifact_probe_forms as _apf
        probes = _apf(token)
    except Exception:
        probes = [token, _loose(token)]
    for probe in dict.fromkeys(probes):
        if _in_db_one(cur, ck, probe):
            return True
    # curated indicators (owner report / manual approval / evidence-derived extractor) count as grounded
    try:
        cur.execute("SELECT 1 FROM case_iocs WHERE case_key=%s AND ioc_value ILIKE %s AND coalesce(source_table,'') NOT IN %s LIMIT 1",
                    (ck, '%' + token + '%', SOFT_IOC))
        if cur.fetchone():
            return True
    except Exception:
        try:
            cur.connection.rollback()
        except Exception:
            pass
    return False


def _in_db_one(cur, ck, token):
    t = '%' + token.replace('%', '') + '%'
    for sql in (
        "SELECT 1 FROM event_logs_v2 WHERE case_key=%s AND (coalesce(command_line,'') ILIKE %s OR coalesce(remote_host,'') ILIKE %s OR payload::text ILIKE %s) LIMIT 1",
        "SELECT 1 FROM filesystem_v2 WHERE case_key=%s AND (file_name ILIKE %s OR coalesce(parent_path,'') ILIKE %s OR payload::text ILIKE %s) LIMIT 1",
        "SELECT 1 FROM program_exec_v2 WHERE case_key=%s AND (coalesce(full_path,'') ILIKE %s OR coalesce(executable_name,'') ILIKE %s OR payload::text ILIKE %s) LIMIT 1",
        "SELECT 1 FROM raw_fallback_v2 WHERE case_key=%s AND payload::text ILIKE %s AND %s=%s LIMIT 1",
        "SELECT 1 FROM tool_alerts_v2 WHERE case_key=%s AND (coalesce(details,'') ILIKE %s OR coalesce(ioc_value,'') ILIKE %s OR coalesce(rule,'') ILIKE %s) LIMIT 1",
    ):
        try:
            cur.execute("SET statement_timeout='20000'")
            cur.execute(sql, (ck, t, t, t))
            if cur.fetchone():
                return True
        except Exception:
            try:
                cur.connection.rollback()
            except Exception:
                pass
    return False


def main():
    truth = json.load(io.open(TRUTH, encoding='utf-8'))['cases']
    stamp = datetime.datetime.now().strftime('%Y%m%d_%H%M')
    os.makedirs(OUTD, exist_ok=True)
    rows, details = [], {}
    with psycopg2.connect(PG_DSN) as c:
        c.autocommit = True
        cur = c.cursor()
        for ck, T in truth.items():
            p = os.path.join(BASE, ck + '.txt')
            if not os.path.exists(p):
                rows.append((ck, '-', '-', '-', '-', '-', 'NO REPORT'))
                continue
            txt = io.open(p, encoding='utf-8', errors='ignore').read()
            L = llm_part(txt)
            Ll = L.lower()
            facts = [m['label'] for m in T.get('must', [])]
            found, missed = [], []
            for m in T.get('must', []):
                (found if re.search(m['re'], Ll) else missed).append(m['label'])
            # artefacts the report itself already marked as «не в доказах» are honest, not fabricated
            _Lm = re.sub(r'\S+\s*⟨не в доказах кейсу⟩', ' ', L)
            ips, doms, exes = candidates(_Lm)
            fab = [x for x in ips + doms + exes if not in_db(cur, ck, x)]
            want = T['verdict']
            attr = []
            concl = Ll
            if want == 'compromised':
                if not INTRUSION_RX.search(concl):
                    attr.append('LLM не описує компрометацію')
                if CALM_RX.search(concl) and not INTRUSION_RX.search(concl[:1500]):
                    attr.append('LLM робить спокійний висновок на скомпрометованому кейсі')
            else:
                _claims = [m for m in ATTACK_CLAIM_RX.finditer(concl)
                           if not _claim_is_denied(concl, m)]
                if _claims:
                    m = _claims[0]
                    attr.append('LLM стверджує атаку на чистому кейсі: «%s»' % concl[max(0, m.start() - 40):m.end() + 40].replace('\n', ' '))
            for rx in T.get('page1_must_not', []):
                mm = re.search(rx, page1(txt).lower())
                if mm:
                    attr.append('заборонена фраза: «%s»' % mm.group(0)[:60])
            ok = not missed and not fab and not attr
            res = 'PASS' if ok else 'FAIL'
            rows.append((ck, '; '.join(facts)[:160], '; '.join(found)[:120], '; '.join(missed) or '—', ', '.join(fab)[:160] or '—', '; '.join(attr)[:160] or '—', res))
            details[ck] = {'want': want, 'facts': facts, 'found': found, 'missed': missed, 'fabricated': fab, 'attribution': attr, 'result': res,
                           'llm_chars': len(L)}
            print('%s %s missed=%d fab=%d attr=%d' % (res, ck[:38], len(missed), len(fab), len(attr)), flush=True)
    md = ['# LLM regression compare — %s' % stamp, '',
          '| case | ключові факти | LLM знайшла | пропустила | вигадала (не в БД) | неправильна атрибуція | результат |', '|---|---|---|---|---|---|---|']
    for r in rows:
        md.append('| ' + ' | '.join(str(x).replace('|', '/') for x in r) + ' |')
    n = sum(1 for r in rows if r[-1] == 'PASS')
    md.append('')
    md.append('**%d/%d PASS**' % (n, len(rows)))
    io.open(os.path.join(OUTD, stamp + '.md'), 'w', encoding='utf-8').write('\n'.join(md) + '\n')
    io.open(os.path.join(OUTD, stamp + '.json'), 'w', encoding='utf-8').write(json.dumps(details, ensure_ascii=False, indent=1))
    print('COMPARE: %d/%d PASS -> %s' % (n, len(rows), os.path.join(OUTD, stamp + '.md')))


if __name__ == '__main__':
    main()
