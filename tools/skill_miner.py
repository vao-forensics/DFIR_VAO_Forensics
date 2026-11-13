#!/usr/bin/env python3
"""Самонавчання: щоночі для кожного користувача виводить 0-2 узагальнені робочі процедури з його
недавніх чатів (локальна модель), пропускає через суддю + детерміновані фільтри приватності
(IP/хеші/пошти/домени/дати) і зберігає ЛИШЕ для цього користувача (scope=user:<id>).
Вміст чатів бачить тільки локальна модель; лог/сповіщення — лише кількості."""
import json, os, re, sqlite3, time, urllib.request, sys
ROOT = os.environ.get("DFIR_ROOT", "/srv/dfir")

DB = "/var/lib/docker/volumes/open-webui/_data/webui.db"
SK = "/var/lib/docker/volumes/open-webui/_data/skills/skills.json"
LLM = os.environ.get("DFIR_PORTAL_LLM", "http://192.168.100.1:1234") + "/v1/chat/completions"
MODEL = "gpt-small-20b"
MAX_PER_USER = 20
DAYS = 7

PRIV = re.compile(r"(\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-f]{32,64}\b|[\w.+-]+@[\w-]+\.[\w.-]+|"
                  r"\b[\w-]+\.(com|net|org|ua|ru|io|info|biz|xyz|top|online)\b|\b20\d\d-\d\d-\d\d\b)", re.I)


def llm(system, user, max_tokens=1200):
    body = {"model": MODEL, "max_tokens": max_tokens, "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    r = json.load(urllib.request.urlopen(urllib.request.Request(LLM, json.dumps(body).encode(),
                  {"Content-Type": "application/json"}), timeout=600))
    return (r["choices"][0]["message"].get("content") or "").strip()


def first_json(txt, opener="[", closer="]"):
    a, b = txt.find(opener), txt.rfind(closer)
    if a < 0 or b <= a:
        return None
    try:
        return json.loads(txt[a:b + 1])
    except Exception:
        return None


def dialog_text(chat_json):
    try:
        d = json.loads(chat_json)
        msgs = d.get("messages") or []
        out = []
        for m in msgs[-12:]:
            c = m.get("content")
            if isinstance(c, str) and c.strip():
                out.append(("К: " if m.get("role") == "user" else "А: ") + c.strip()[:700])
        return "\n".join(out)
    except Exception:
        return ""


EXTRACT = ("Ти аналізуєш робочі діалоги одного фахівця з асистентом, щоб запамʼятати, ЯК він працює. "
           "Виділи до 2 УЗАГАЛЬНЕНИХ робочих процедур, які допоможуть цьому фахівцю наступного разу "
           "(типові задачі, послідовність кроків, бажаний формат). СУВОРО без: імен, IP, хешів, доменів, "
           "email, назв справ/організацій, дат. Якщо нічого вартого — поверни []. Формат — ТІЛЬКИ JSON-масив: "
           "[{\"title\":\"...\",\"triggers\":[5-8 ключових слів укр/англ],\"body\":\"3-5 нумерованих кроків\"}]")
JUDGE = ("Ти суворий рецензент бази знань. Оціни процедуру. Прийняти лише якщо: узагальнена (жодних "
         "конкретних імен/IP/хешів/доменів/справ), технічно коректна, корисна, не тривіальна. "
         "Відповідь ТІЛЬКИ JSON: {\"ok\":true|false,\"reason\":\"...\"}")


def main():
    if not os.path.exists(SK):
        print("нема skills.json"); return
    data = json.load(open(SK, encoding="utf-8"))
    skills = data.get("skills", [])
    c = sqlite3.connect(DB)
    since = int(time.time()) - DAYS * 86400
    added_total, users_hit = 0, 0
    for uid, name in c.execute("select id,name from user"):
        chats = c.execute("select chat from chat where user_id=? and updated_at>? order by updated_at desc limit 10",
                          (uid, since)).fetchall()
        text = "\n\n---\n\n".join(t for t in (dialog_text(r[0]) for r in chats if r[0]) if len(t) > 300)[:9000]
        if len(text) < 600:
            continue
        try:
            cands = first_json(llm(EXTRACT, text)) or []
        except Exception as e:
            print("LLM помилка для користувача", uid[:8], repr(e)[:80]); continue
        mine = [s for s in skills if s.get("scope") == "user:%s" % uid]
        have = {s["title"].lower() for s in mine}
        added = 0
        for cand in cands[:2]:
            if not isinstance(cand, dict):
                continue
            title, body = str(cand.get("title", "")).strip(), str(cand.get("body", "")).strip()
            trig = [str(t).lower() for t in cand.get("triggers", []) if str(t).strip()][:8]
            if len(title) < 5 or len(body) < 40 or len(trig) < 3:
                continue
            if PRIV.search(title + " " + body + " " + " ".join(trig)):
                continue  # приватність: конкретика зі справ — відкидаємо
            if title.lower() in have:
                continue
            try:
                verdict = first_json(llm(JUDGE, "Назва: %s\nКроки:\n%s" % (title, body), 200), "{", "}") or {}
            except Exception:
                verdict = {}
            if not verdict.get("ok"):
                continue
            skills.append({"id": "usr-%s-%d" % (uid[:8], int(time.time() * 1000) % 10**9), "scope": "user:%s" % uid,
                           "title": title, "triggers": trig, "body": body, "source": "auto",
                           "status": "approved", "created": int(time.time()), "uses": 0})
            added += 1
        # не більше MAX_PER_USER авто-скілів на людину — найстаріші йдуть
        mine = [s for s in skills if s.get("scope") == "user:%s" % uid and s.get("source") == "auto"]
        if len(mine) > MAX_PER_USER:
            drop = {s["id"] for s in sorted(mine, key=lambda s: s["created"])[:len(mine) - MAX_PER_USER]}
            skills = [s for s in skills if s["id"] not in drop]
        if added:
            added_total += added; users_hit += 1
    data["skills"] = skills
    tmp = SK + ".tmp"
    json.dump(data, open(tmp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    os.replace(tmp, SK); os.chmod(SK, 0o666)
    print("нових процедур: %d (користувачів: %d); усього скілів: %d" % (added_total, users_hit, len(skills)))
    if added_total and "--quiet" not in sys.argv:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import portal_qa
            portal_qa.notify("🧠 Самонавчання: асистент засвоїв %d нових робочих процедур для %d користувачів (усе перевірено суддею, без даних справ)." % (added_total, users_hit))
        except Exception:
            pass


if __name__ == "__main__":
    main()
