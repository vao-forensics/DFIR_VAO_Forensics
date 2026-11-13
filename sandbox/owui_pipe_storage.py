"""
title: 📊 Сховище користувачів (адмін)
author: DFIR
version: 0.1.0
description: Таблиця «хто скільки займає»: проєкти/бази знань, тимчасові файли, найближче видалення, ліміт. Лише для адміністратора; модель не викликається.
"""
import sqlite3, time
from pydantic import BaseModel

DB = "file:/app/backend/data/webui.db?mode=ro"


class Pipe:
    class Valves(BaseModel):
        quota_gb: float = 5.0
        ttl_hours: int = 24

    def __init__(self):
        self.valves = self.Valves()

    def pipes(self):
        return [{"id": "storage", "name": "📊 Сховище користувачів"}]

    def pipe(self, body: dict, __user__: dict = None) -> str:
        if not __user__ or __user__.get("role") != "admin":
            return "Лише для адміністратора."
        c = sqlite3.connect(DB, uri=True, timeout=5)
        try:
            users = c.execute("select id, coalesce(name,''), coalesce(email,''), role from user").fetchall()
            files = c.execute("select id, user_id, coalesce(json_extract(meta,'$.size'),0), created_at from file").fetchall()
            keep = {r[0] for r in c.execute("select file_id from knowledge_file")}
            blobs = [r[0] for r in c.execute("select coalesce(data,'') || coalesce(items,'') from folder")]
            nkb = dict(c.execute("select user_id, count(*) from knowledge group by 1").fetchall())
            nproj = dict(c.execute("select user_id, count(*) from folder group by 1").fetchall())
        finally:
            c.close()
        for fid, *_ in files:
            if fid not in keep and any(fid in b for b in blobs):
                keep.add(fid)
        gb = lambda b: ("%.2f" % (b / 1073741824)).replace(".", ",")
        q = self.valves.quota_gb * 1073741824
        rows, total = [], 0
        for uid, name, email, role in users:
            mine = [f for f in files if f[1] == uid]
            tot = sum(int(f[2] or 0) for f in mine)
            kept = sum(int(f[2] or 0) for f in mine if f[0] in keep)
            temp = [f for f in mine if f[0] not in keep]
            nxt = min((int(f[3] or 0) for f in temp), default=0)
            when = time.strftime("%d.%m %H:%M", time.localtime(nxt + self.valves.ttl_hours * 3600)) if nxt else "—"
            total += tot
            bar = "▓" * min(10, int(round(10 * tot / q))) + "░" * (10 - min(10, int(round(10 * tot / q))))
            flag = " ⚠" if tot > q else ""
            rows.append((tot, "| %s | %s | %s %s ГБ%s | %s | %s (%d) | %d | %d | %s |" % (
                name or "—", email or "—", bar, gb(tot), flag, gb(kept), gb(tot - kept), len(temp),
                nproj.get(uid, 0), nkb.get(uid, 0), when)))
        rows.sort(key=lambda r: -r[0])
        out = ["**Сховище Open WebUI** (ліміт %s ГБ на людину; тимчасові файли видаляються через %d год)\n" % (gb(q), self.valves.ttl_hours),
               "| Користувач | Email | Усього | У проєктах, ГБ | Тимчасові, ГБ (файлів) | Проєктів | Баз знань | Найближче видалення |",
               "|---|---|---|---|---|---|---|---|"] + [r[1] for r in rows]
        out.append("\nРазом: **%s ГБ** у %d користувачів. Оновлюється щоразу, коли ви пишете сюди." % (gb(total), len(users)))
        return "\n".join(out)
