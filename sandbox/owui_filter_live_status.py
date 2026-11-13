"""
title: DFIR — живий статус моделі
author: DFIR
version: 0.1.0
description: Показує в чаті гарний рядок завантаження моделі на карти (прогрес-бар) і коли вона готова. Щоб користувач бачив, що йде робота, а не зависло. Без технічних деталей.
"""
import json, time, threading, urllib.request, sqlite3, asyncio
from pydantic import BaseModel

GPU = "http://192.168.100.1:1235/gpu"
SWAP = "http://192.168.100.1:1234"


def _bar(pct, n=14):
    fll = int(pct / 100 * n)
    return "▰" * fll + "▱" * (n - fll)


class Filter:
    class Valves(BaseModel):
        priority: int = 1

    def __init__(self):
        self.valves = self.Valves()

    def _status(self):
        try:
            return json.load(urllib.request.urlopen(GPU, timeout=3))
        except Exception:
            return None

    def _resolve(self, mid):
        # OWUI-модель -> llama-swap id (база), бо прогрів іде за реальним id
        try:
            c = sqlite3.connect("/app/backend/data/webui.db")
            r = c.execute("select base_model_id from model where id=?", (mid,)).fetchone()
            return r[0] if r and r[0] else mid
        except Exception:
            return mid

    def _warm(self, swap_id):
        try:
            body = json.dumps({"model": swap_id, "messages": [{"role": "user", "content": "ok"}], "max_tokens": 1}).encode()
            urllib.request.urlopen(urllib.request.Request(SWAP + "/v1/chat/completions", body, {"Content-Type": "application/json"}), timeout=220)
        except Exception:
            pass

    async def inlet(self, body: dict, __event_emitter__=None, __user__=None) -> dict:
        model = body.get("model")
        if not model or not __event_emitter__:
            return body
        target = self._resolve(model)
        st = self._status()
        # уже прогріта саме ця модель — нічого не показуємо
        if st and st.get("model") == target and not st.get("loading"):
            return body

        async def emit(desc, done=False):
            try:
                await __event_emitter__({"type": "status", "data": {"description": desc, "done": done}})
            except Exception:
                pass

        est = 90 if any(k in str(target).lower() for k in ["120b", "big", "super", "122b", "nemotron", "glm", "122", "bolt"]) else 35
        threading.Thread(target=self._warm, args=(target,), daemon=True).start()
        t0 = time.time()
        await emit("⏳ Вмикаю модель…")
        while True:
            el = time.time() - t0
            s = self._status()
            ready = s and s.get("model") == target and not s.get("loading")
            if ready or el > 210:
                break
            pct = min(96, int(el / est * 100))
            await emit("⏳ Готую модель до роботи   %s  %d%%" % (_bar(pct), pct))
            await asyncio.sleep(2)
        await emit("⚡ Модель готова — працюю над відповіддю", done=True)
        return body
