import json, re, subprocess, os, collections
os.chdir('/srv/dfir')
cfg = json.loads(subprocess.run(['docker', 'compose', 'config', '--format', 'json'], capture_output=True, text=True, check=True).stdout)
SECRET = re.compile(r'TOKEN|PASSWORD|PASS|SECRET|KEY|DSN', re.I)
TOPO = re.compile(r'https?://|\b\d{1,3}(\.\d{1,3}){3}\b|_URL$|_BASE$|_HOST$|_IP$|_IFACE$|_SUBNET$|_PREFIX$|_PANEL$')
rows = collections.OrderedDict()
for name, svc in cfg['services'].items():
    env = svc.get('environment') or {}
    for k, v in (env.items() if isinstance(env, dict) else []):
        v = '' if v is None else str(v)
        if SECRET.search(k) and not k.endswith('_URL'):
            continue
        if TOPO.search(k) or TOPO.search(v):
            rows.setdefault(k, set()).add((name, v))
code = collections.OrderedDict()
for root in ('services/case_maintainer',):
    for dp, _, fs in os.walk(root):
        if '/guards' in dp or '__pycache__' in dp:
            continue
        for f in fs:
            if not f.endswith('.py'):
                continue
            p = os.path.join(dp, f)
            for m in re.finditer(r"(?:getenv|environ\.get)\(\s*['\"]([A-Z0-9_]+)['\"]\s*,\s*['\"](https?://[^'\"]+)['\"]", open(p, encoding='utf-8', errors='replace').read()):
                code.setdefault(m.group(1), set()).add((m.group(2), p.replace('services/case_maintainer/', '')))
wf = open('services/n8n_workflow_export.json', encoding='utf-8').read()
n8n = collections.Counter(re.findall(r'\b(?:192\.168|10\.8|10\.7|10\.244)\.\d+\.\d+(?::\d+)?', wf))
out = ['# Топологія DFIR Bot — усі адреси й порти в одному місці', '',
       'Згенеровано автоматично (`tools/site_doc.py`) 18.10.2026. Секрети сюди не потрапляють.',
       'Переїзд на інше залізо з ТИМИ САМИМИ адресами (план `infra/linux`) нічого тут не змінює.',
       'Інші адреси = змінити значення в `.env`/compose (рядки 1–2), у n8n (рядок 3) і перевірити 90_verify.', '',
       '## 1. Змінні оточення контейнерів (docker-compose.yml)', '', '| Змінна | Значення | Сервіси |', '|---|---|---|']
for k, s in rows.items():
    by = collections.defaultdict(list)
    for n, v in s:
        by[v].append(n)
    for v, ns in by.items():
        out.append('| `%s` | `%s` | %s |' % (k, v[:80], ', '.join(sorted(ns))))
out += ['', '## 2. Значення за замовчуванням у коді бота (діють, якщо змінна не задана)', '',
        '| Змінна | За замовчуванням | Файл |', '|---|---|---|']
for k, s in code.items():
    for v, p in sorted(s):
        out.append('| `%s` | `%s` | %s |' % (k, v, p))
out += ['', '## 3. Адреси, вшиті у воркфлоу n8n (`services/n8n_workflow_export.json`)', '',
        '| Адреса | Скільки разів |', '|---|---|']
for a, n in n8n.most_common():
    out.append('| `%s` | %d |' % (a, n))
out += ['', '## 4. Поза ВМ', '',
        '* Хост: llama-swap :1234, whisper :8771, image :8772, diarize :8773, tts :8774, embed CPU :5899,',
        '  gpu-agent :8788, llm-control :8790, file server :8099 — на `192.168.100.1` і `192.168.134.1`.',
        '* VPN: WireGuard-хаб на VPS; ВМ = `CHANGE_ME_DFIR_LINK_IP` (wgbot, користувачі: лише :8080 і :1234 через llm-gw) і `10.7.0.3` (dfir).',
        '* Інтернет: лише вебхук Telegram через ngrok → webhook-gate (Caddy).', '']
open('docs/SITE_CONFIG.md', 'w', encoding='utf-8').write('\n'.join(out))
print(len(rows), 'env vars,', sum(len(s) for s in code.values()), 'code defaults,', len(n8n), 'n8n addresses')
