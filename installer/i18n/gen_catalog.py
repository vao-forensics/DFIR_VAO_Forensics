#!/usr/bin/env python3
"""Generate installer/i18n/<code>.sh from en.sh with the local LLM.

Keys go to the model in JSON batches, so a two-word label still has its neighbours as
context (one key at a time, "copy from here" came back as "Sure, just paste the text").
Every value is checked: same printf placeholders, same line count, protected literals
(commands, paths, names) kept, sane length, no chatty assistant reply. A value that fails
twice stays out of the file and the installer shows the English one for that key.

  python3 installer/i18n/gen_catalog.py pl de es      # writes pl.sh de.sh es.sh
"""
import json, os, re, subprocess, sys, urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
URL = os.environ.get('LLM', 'http://172.17.0.1:1234') + '/v1/chat/completions'
MODEL = os.environ.get('MODEL', 'gpt-small-20b')
NAMES = {'pl': 'Polish', 'de': 'German', 'es': 'Spanish', 'fr': 'French', 'pt': 'Portuguese (Portugal)',
         'it': 'Italian'}
# literal pieces that must survive untouched
PROTECT = re.compile(r'(sudo [^ ,.;)]+(?: [^ ,.;)]+)?|\./install\.sh|state/[\w./]+|installer/[\w./]+|docs/[\w./]+'
                     r'|https?://[^\s<>"]*[^\s<>".,;:)]|@\w+|/start|/language|dfir-seal-1:\S*|%s|\b[A-Z][A-Z0-9_]{2,}\b'
                     r'|ChatGPT|Gemini|Telegram|WireGuard|ngrok|Docker|NVIDIA|OpenRouter|BotFather|chat_id'
                     r'|llama-swap|n8n)')
CHATTY = re.compile(r"(?i)\b(sure|translat\w*|here is|here's|paste the text|i can|i'm sorry|cannot help)\b")
SYSTEM = ('You translate the user interface of a Linux installer (the setup wizard of a Telegram DFIR bot) from '
          'English to {lang}. You get a JSON object {{key: English text}}; key names hint at the context '
          '(q_ question, h_ help text, o_ option label, d_ option description, step_ step title, err_ error). '
          'Return ONLY a JSON object with the SAME keys and the translated texts. Keep every line break, every '
          '%s placeholder, commands, file paths, URLs, product names and "?" (the help key) verbatim. Short '
          'labels stay short. Polite form, plain words a non-expert understands.')


def load_en(path=None):
    """Catalogue as {key: text}, read by bash itself (the format is bash, quoting included)."""
    out = subprocess.run(['bash', '-c', 'declare -A T; source "$1"; for k in "${!T[@]}"; do printf "%s\\0%s\\0" "$k" "${T[$k]}"; done',
                          '_', path or os.path.join(ROOT, 'en.sh')], capture_output=True, check=True).stdout.decode()
    parts = out.split('\0')[:-1]
    return dict(zip(parts[0::2], parts[1::2]))


def order_keys():
    return re.findall(r'^\[([^\]]+)\]=', open(os.path.join(ROOT, 'en.sh'), encoding='utf-8').read(), re.M)


def llm(lang, items):
    """items: {key: english}. Returns {key: translation}; keys may be missing."""
    src = json.dumps(items, ensure_ascii=False)
    body = {'model': MODEL, 'temperature': 0.2, 'max_tokens': 2000 + len(src) * 4,
            'reasoning_effort': 'low', 'chat_template_kwargs': {'reasoning_effort': 'low'},
            'messages': [{'role': 'system', 'content': SYSTEM.format(lang=lang_name(lang))},
                         {'role': 'user', 'content': src}]}
    req = urllib.request.Request(URL, json.dumps(body).encode(), {'Content-Type': 'application/json'})
    r = json.load(urllib.request.urlopen(req, timeout=600))
    out = (r['choices'][0]['message'].get('content') or '').strip()
    out = out[out.find('{'):out.rfind('}') + 1]
    try:
        d = json.loads(out)
    except Exception:
        return {}
    return {k: v.strip() for k, v in d.items() if k in items and isinstance(v, str)}


def ok(src, dst):
    if not dst or dst.count('%s') != src.count('%s') or dst.count('\n') != src.count('\n'):
        return False
    if CHATTY.search(dst) and not CHATTY.search(src):
        return False
    if len(src) >= 12 and not (0.4 <= len(dst) / len(src) <= 2.6):
        return False
    # a value that is ONE capitalised word (ERROR) is a label to translate, not a literal
    return all(p in dst for p in PROTECT.findall(src) if p != src.strip())


def q(v):
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`') + '"'


def lang_name(code):
    """English name of the language: known ones by table, any other ISO 639 code described for the model."""
    return NAMES.get(code) or "the language with ISO 639 code '%s'" % code


def main(lang):
    en, keys = load_en(), order_keys()
    path = os.path.join(ROOT, lang + '.sh')
    have = {}
    if os.path.exists(path + '.part'):
        have = json.load(open(path + '.part', encoding='utf-8'))
    elif os.path.exists(path):
        have = load_en(path)     # an existing catalogue keeps its values; only missing keys are asked
    todo = []
    for k in keys:
        if k in have:
            continue
        if k in ('yes_no_Y', 'yes_no_N') or not re.search('[A-Za-z]{2}', en[k]):
            have[k] = None
        else:
            todo.append(k)
    batches, cur, size = [], [], 0
    for k in todo:
        if cur and size + len(en[k]) > 1500:
            batches.append(cur)
            cur, size = [], 0
        cur.append(k)
        size += len(en[k])
    if cur:
        batches.append(cur)
    for b in batches:
        for _ in range(3):
            left = [k for k in b if not have.get(k)]
            if not left:
                break
            try:
                res = llm(lang, {k: en[k] for k in left})
            except Exception as e:
                print('llm error', left[:3], e, file=sys.stderr)
                continue
            for k in left:
                if ok(en[k], res.get(k, '')):
                    have[k] = '\n'.join(line.rstrip() for line in res[k].split('\n'))
        for k in b:
            have.setdefault(k, None)
        json.dump(have, open(path + '.part', 'w', encoding='utf-8'), ensure_ascii=False)
    fails = [k for k in todo if not have.get(k)]
    lines = ['# %s: generated from en.sh by the local LLM (installer/i18n/gen_catalog.py), checked by rules only.' % lang_name(lang),
             '# Keys missing here fall back to English.', 'T=(']
    for k in keys:
        if have.get(k):
            lines.append('[%s]=%s' % (k, q(have[k])))
    lines.append(')')
    open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(lines) + '\n')
    os.remove(path + '.part')
    print(lang, 'keys', len(keys), 'translated', sum(1 for k in keys if have.get(k)), 'fallback', fails, flush=True)


if __name__ == '__main__':
    for lang in sys.argv[1:]:
        main(lang)
