#!/usr/bin/env python3
"""Нічний оновлювач профілів користувачів: читає останні чати кожного → локальна модель
виводить короткий профіль (напрям, типові задачі, стиль). НЕ вигадує. Профіль у volume OWUI."""
import json, os, sqlite3, urllib.request, sys
ROOT = os.environ.get("DFIR_ROOT", "/srv/dfir")

DB = "/var/lib/docker/volumes/open-webui/_data/webui.db"
PROF_DIR = "/var/lib/docker/volumes/open-webui/_data/user_profiles"
LLM = os.environ.get("DFIR_PORTAL_LLM", "http://192.168.100.1:1234") + "/v1/chat/completions"
MODEL = "gpt-small-20b"
os.makedirs(PROF_DIR, exist_ok=True)

SYS = ("Ти аналізуєш повідомлення одного користувача DFIR-асистента, щоб скласти короткий робочий "
       "профіль. Визнач ЛИШЕ те, що реально видно: напрям (напр. логи Windows / форензика телефонів / "
       "документи / мережа), типові задачі, бажаний стиль відповіді. 3-5 пунктів, українською, стисло. "
       "НЕ вигадуй і не додавай нічого, чого немає в повідомленнях. Якщо даних замало — відповідай рівно "
       "'(недостатньо даних)'. Не згадуй конкретних справ чи імен клієнтів.")


def user_msgs(chat_json):
    out = []
    try:
        d = json.loads(chat_json)
        msgs = d.get("messages")
        if not msgs and isinstance(d.get("history"), dict):
            msgs = list(d["history"].get("messages", {}).values()) if isinstance(d["history"].get("messages"), dict) else None
        for m in (msgs or []):
            if m.get("role") == "user":
                c = m.get("content")
                if isinstance(c, str) and c.strip():
                    out.append(c.strip()[:500])
    except Exception:
        pass
    return out


def llm(text):
    body = {"model": MODEL, "messages": [{"role": "system", "content": SYS},
            {"role": "user", "content": "Повідомлення користувача:\n\n" + text}],
            "max_tokens": 400, "temperature": 0.3}
    req = urllib.request.Request(LLM, json.dumps(body).encode(), {"Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=600))
    return (r["choices"][0]["message"].get("content") or "").strip()


def main():
    c = sqlite3.connect(DB)
    users = c.execute("select id,name,role from user").fetchall()
    for uid, name, role in users:
        chats = c.execute("select chat from chat where user_id=? and (archived=0 or archived is null) order by updated_at desc limit 8", (uid,)).fetchall()
        msgs = []
        for (cj,) in chats:
            if cj:
                msgs += user_msgs(cj)
        msgs = msgs[:40]
        if len(msgs) < 3:
            print("%s (%s): замало активності (%d повідомл.) — пропуск" % (name, uid[:8], len(msgs)))
            continue
        text = "\n".join("- " + m for m in msgs)[:4000]
        try:
            prof = llm(text)
        except Exception as e:
            print("%s: помилка LLM %s" % (name, repr(e)[:80])); continue
        if "недостатньо даних" in prof.lower() or len(prof) < 15:
            print("%s (%s): модель — недостатньо даних" % (name, uid[:8])); continue
        with open(os.path.join(PROF_DIR, "%s.md" % uid), "w", encoding="utf-8") as f:
            f.write(prof)
        print("%s (%s): профіль оновлено (%d символів)" % (name, uid[:8], len(prof)))


if __name__ == "__main__":
    main()
