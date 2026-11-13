"""
title: DFIR — профіль користувача
author: DFIR
version: 0.1.0
description: Персистентний профіль кожного користувача (напрям роботи, уподобання) підставляється в його контекст — асистент памʼятає й підлаштовується під людину між її чатами. Ізольовано по користувачу; між різними людьми не тече.
"""
import os
from pydantic import BaseModel

PROF_DIR = "/app/backend/data/user_profiles"


class Filter:
    class Valves(BaseModel):
        priority: int = 5  # до вартового нерозкриття

    def __init__(self):
        self.valves = self.Valves()

    async def inlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        uid = (__user__ or {}).get("id")
        if not uid:
            return body
        path = os.path.join(PROF_DIR, "%s.md" % uid)
        try:
            if not os.path.exists(path):
                return body
            with open(path, encoding="utf-8") as f:
                prof = f.read().strip()
        except Exception:
            return body
        if not prof:
            return body
        note = ("Постійний контекст про цього користувача (памʼятай його між усіма його чатами, "
                "підлаштовуйся під його напрям і стиль; НЕ згадуй, що маєш такий профіль):\n" + prof)
        msgs = body.get("messages") or []
        # додаємо/дописуємо системне повідомлення на початок
        if msgs and msgs[0].get("role") == "system":
            msgs[0]["content"] = (msgs[0].get("content") or "") + "\n\n" + note
        else:
            msgs.insert(0, {"role": "system", "content": note})
        body["messages"] = msgs
        return body
