"""
title: DFIR — робочі процедури
author: DFIR
version: 0.1.0
description: Тихо додає 1-2 доречні робочі процедури (глобальні + персональні цього користувача) до контексту асистента, щоб відповіді були точнішими й підлаштовувались під людину.
"""
import json, os, re
from pydantic import BaseModel

SK = "/app/backend/data/skills/skills.json"


class Filter:
    class Valves(BaseModel):
        priority: int = 6
        max_skills: int = 2

    def __init__(self):
        self.valves = self.Valves()
        self._cache = (0, [])

    def _load(self):
        try:
            mt = os.path.getmtime(SK)
            if mt != self._cache[0]:
                d = json.load(open(SK, encoding="utf-8"))
                self._cache = (mt, [s for s in d.get("skills", []) if s.get("status") == "approved"])
        except Exception:
            pass
        return self._cache[1]

    @staticmethod
    def _score(text, triggers):
        sc = 0
        for t in triggers:
            t = t.lower()
            if len(t) <= 3:
                if re.search(r"(?<![\w])" + re.escape(t) + r"(?![\w])", text):
                    sc += 1
            elif t in text:
                sc += 1
        return sc

    async def inlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        msgs = body.get("messages") or []
        last = ""
        for m in reversed(msgs):
            if m.get("role") == "user":
                c = m.get("content")
                last = c if isinstance(c, str) else " ".join(p.get("text", "") for p in c if isinstance(p, dict)) if isinstance(c, list) else ""
                break
        if not last:
            return body
        uid = (__user__ or {}).get("id")
        text = last.lower()
        cand = []
        for s in self._load():
            scope = s.get("scope", "global")
            if scope != "global" and scope != "user:%s" % uid:
                continue  # персональні скіли інших людей НЕ підтягуємо
            sc = self._score(text, s.get("triggers", []))
            if sc > 0:
                cand.append((sc, s))
        if not cand:
            return body
        cand.sort(key=lambda x: -x[0])
        pick = [s for _, s in cand[: self.valves.max_skills]]
        note = ("Корисні робочі процедури (застосуй, якщо доречно до запиту; не згадуй, що маєш їх):\n"
                + "\n\n".join("### %s\n%s" % (s["title"], s["body"]) for s in pick))
        if msgs and msgs[0].get("role") == "system":
            msgs[0]["content"] = (msgs[0].get("content") or "") + "\n\n" + note
        else:
            msgs.insert(0, {"role": "system", "content": note})
        body["messages"] = msgs
        return body
