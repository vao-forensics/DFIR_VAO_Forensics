"""
title: DFIR — диспетчер моделей (пріоритет 120B)
author: DFIR
version: 0.1.0
description: Моделі ділять одні відеокарти. Якщо на картах уже 120B, а користувач вибрав іншу модель, відповідь дає 120B (без 2–4 хв перезавантаження) і чат про це каже. Потрібна саме вибрана модель — допишіть /чекати.
"""
import json, time, urllib.request
from pydantic import BaseModel

NAMES = {"big-120b": "🐘 Велика 120B", "agent-30b": "🔓 Універсальна", "reasoner-31b": "🧠 Аналітика/звіти",
         "gpt-small-20b": "⚡ Швидка", "vision-7b": "🖼 Зображення"}


class Filter:
    class Valves(BaseModel):
        swap_url: str = "http://192.168.100.1:1234/running"
        big_model: str = "big-120b"
        reroute: str = "agent-30b,reasoner-31b,gpt-small-20b"  # що можна підмінити на 120B (зображення — ні)
        wait_tag: str = "/чекати"
        priority: int = 0

    def __init__(self):
        self.valves = self.Valves()

    def _running(self):
        try:
            with urllib.request.urlopen(self.valves.swap_url, timeout=3) as r:
                d = json.load(r)
            return {m.get("model"): m.get("state") for m in d.get("running", [])}
        except Exception:
            return None

    async def inlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        req = body.get("model") or ""
        run = self._running()
        if run is None:
            return body
        msgs = body.get("messages") or []
        last = msgs[-1] if msgs and msgs[-1].get("role") == "user" else None
        text = last.get("content") if last and isinstance(last.get("content"), str) else ""
        wait = bool(text) and self.valves.wait_tag in text
        if wait and last is not None:
            last["content"] = text.replace(self.valves.wait_tag, "").strip() or text
        big = self.valves.big_model
        big_on = run.get(big) in ("ready", "starting")
        say = None
        if req != big and big_on and req in [x.strip() for x in self.valves.reroute.split(",")] and not wait:
            body["model"] = big
            say = ("Зараз на відеокартах завантажена %s (нею користуються інші). Відповідає вона, щоб не чекати 2–4 хв "
                   "перезавантаження. Потрібна саме «%s» — допишіть до повідомлення %s." % (NAMES[big], NAMES.get(req, req), self.valves.wait_tag))
        elif req == big and not big_on:
            say = "Завантажую %s на відеокарти — перша відповідь за 2–4 хв, далі швидко." % NAMES[big]
        elif req != big and run.get(req) not in ("ready",):
            if big_on:
                say = "«%s» чекає, поки звільняться відеокарти від %s (до 2–4 хв)." % (NAMES.get(req, req), NAMES[big])
            else:
                say = "Завантажую «%s» (до хвилини)…" % NAMES.get(req, req)
        if say and __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": say, "done": True}})
        return body
