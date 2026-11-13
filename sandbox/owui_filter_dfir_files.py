"""
title: DFIR — розбір прикріплених файлів у пісочниці
author: DFIR
version: 0.4.2
description: Будь-який прикріплений файл (архів, у т.ч. запаролений архів збирача, лог, CSV, evtx, БД, документ) розбирається в ізольованій пісочниці; модель отримує структурований зміст. Плюс правило проти зациклення.
"""
import asyncio
import os
import time, uuid
import json
import urllib.request
from pydantic import BaseModel

RULES = (
    "Правила роботи з файлами (обовʼязково):\n"
    "1. Якщо користувач просить проаналізувати файл, а файлу немає ні в повідомленні, ні в джерелах проєкту — "
    "коротко попроси його завантажити. НЕ вгадуй назви файлів.\n"
    "2. Не повторюй однаковий виклик інструмента більше одного разу; якщо результату нема — скажи про це.\n"
    "3. Спирайся лише на наданий розбір пісочниці; не вигадуй вмісту файлів, шляхів чи подій.\n"
    "4. Розділяй факти (з розбору) і припущення. Індикатори — це підказки до перевірки, а не доведена атака.\n"
)


# документи читає рідний екстрактор OWUI (текст -> модель); пісочниця — для форензик-артефактів
DOC_EXT = {".pdf",".doc",".docx",".odt",".rtf",".txt",".md",".html",".htm",".pptx",".ppt",".xlsx",".xls",".ods",".epub",".csv",".tsv",".tab",".log",".json",".jsonl",".ndjson",".xml",".yaml",".yml",".ini",".conf",".cfg"}


class Filter:
    class Valves(BaseModel):
        api_url: str = "http://172.18.0.1:8791/analyze"
        token: str = ""
        max_chars_per_file: int = 30000
        timeout_s: int = 1100
        max_mb: int = 2048
        big_upload_hint: str = ""
        progress_every_s: int = 5
        quota_gb: float = 5.0          # м'який ліміт простору на користувача (проєкти + тимчасові)
        ttl_hours: int = 24            # тимчасові файли з чату видаляються через стільки годин
        show_usage: bool = True

    def __init__(self):
        self.valves = self.Valves()
        # НЕ file_handler: інакше OWUI вимикає рідний пошук і для джерел проєкту.
        # Ми самі прибираємо з тіла лише ті файли, які розібрала пісочниця.
        self.file_handler = False

    def _get(self, sub):
        base = self.valves.api_url.rsplit("/", 1)[0]
        try:
            with urllib.request.urlopen(base + sub, timeout=5) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            return {}

    def _progress_text(self, name, ticket, t0):
        q = self._get("/queue/owui_" + ticket).get("position", 0)
        el = int(time.time() - t0)
        if q:
            return "«%s»: у черзі, перед вами %d (чекаєте %d с)" % (name, q - 1, el)
        st = self._get("/status")
        mdl = ", ".join(m.get("model", "") for m in st.get("models", []) if isinstance(m, dict)) if isinstance(st.get("models"), list) else ""
        return "Розбираю «%s» в ізольованій пісочниці… %d с%s" % (name, el, (" · модель: " + mdl) if mdl else "")

    def _call(self, path, ticket="", who=None):
        req = urllib.request.Request(
            self.valves.api_url,
            data=json.dumps({"path": path, "ticket": ticket, "user": who or {}}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Token": self.valves.token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.valves.timeout_s) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                return json.loads(e.read().decode("utf-8"))
            except Exception:
                return {"ok": False, "error": "HTTP %s" % e.code}
        except Exception as e:
            return {"ok": False, "error": str(e)}


    def _usage(self, uid):
        """(усього_байт, у_проєктах_байт, тимчасові_байт, найближче_видалення_ts) для користувача"""
        import sqlite3
        c = sqlite3.connect("file:/app/backend/data/webui.db?mode=ro", uri=True, timeout=5)
        try:
            rows = c.execute("select id, coalesce(json_extract(meta,'$.size'),0), created_at from file where user_id=?", (uid,)).fetchall()
            keep = {r[0] for r in c.execute("select file_id from knowledge_file where user_id=?", (uid,))}
            for (d,) in c.execute("select coalesce(data,'') || coalesce(items,'') from folder where user_id=?", (uid,)):
                for fid, _, _ in rows:
                    if fid in d:
                        keep.add(fid)
        finally:
            c.close()
        tot = sum(int(r[1] or 0) for r in rows)
        kept = sum(int(r[1] or 0) for r in rows if r[0] in keep)
        temp_ts = [int(r[2] or 0) for r in rows if r[0] not in keep and r[2]]
        nxt = (min(temp_ts) + self.valves.ttl_hours * 3600) if temp_ts else None
        return tot, kept, tot - kept, nxt

    def _usage_line(self, uid):
        tot, kept, temp, nxt = self._usage(uid)
        gb = lambda b: ("%.1f" % (b / 1073741824)).replace(".", ",")
        q = max(self.valves.quota_gb, 0.1)
        filled = min(10, int(round(10 * tot / (q * 1073741824))))
        bar = "▓" * filled + "░" * (10 - filled)
        when = (" · найближче видалення о " + time.strftime("%H:%M", time.localtime(nxt))) if nxt else ""
        return tot, "Простір: %s %s / %s ГБ · у проєктах %s · тимчасові %s (видаляються через %d год)%s" % (
            bar, gb(tot), gb(q * 1073741824), gb(kept), gb(temp), self.valves.ttl_hours, when)

    @staticmethod
    async def _file_info(f):
        inner = f.get("file") if isinstance(f.get("file"), dict) else {}
        path = inner.get("path") or f.get("path") or ""
        name = inner.get("filename") or f.get("name") or (inner.get("meta") or {}).get("name") or "файл"
        fid = f.get("id") or inner.get("id")
        if (not path) and fid:
            # browser/API payloads often carry only the id -> resolve from OWUI's DB
            try:
                from open_webui.models.files import Files
                rec = await Files.get_file_by_id(fid)
                if rec:
                    path = rec.path or ""
                    name = rec.filename or name
            except Exception:
                pass
        return path, name

    @staticmethod
    def _who(user, request, name):
        """who uploaded it, for the admin audit (portal_upload_audit_v1); not shown to the model"""
        u = user if isinstance(user, dict) else {}
        ip = ""
        try:
            h = request.headers if request is not None else {}
            ip = (h.get("x-real-ip") or (h.get("x-forwarded-for") or "").split(",")[0].strip()
                  or (request.client.host if request is not None and request.client else ""))
        except Exception:
            pass
        return {"id": u.get("id", ""), "email": u.get("email", ""), "name": u.get("name", ""), "ip": ip, "file_name": name}

    async def inlet(self, body: dict, __files__=None, __event_emitter__=None, __user__=None, __request__=None) -> dict:
        files = __files__ or body.get("files") or []
        parts = []
        handled = set()
        uid = (__user__ or {}).get("id") if isinstance(__user__, dict) else None
        used = 0
        if uid and self.valves.show_usage and __event_emitter__:
            try:
                used, line = self._usage_line(uid)
                await __event_emitter__({"type": "status", "data": {"description": line, "done": True}})
            except Exception:
                pass
        over = used > self.valves.quota_gb * 1073741824
        for f in files:
            if not isinstance(f, dict):
                continue
            if f.get("type") in ("collection", "folder", "web_search", "note") or f.get("collection_name") or f.get("knowledge"):
                continue  # джерела проєкту -> рідний пошук OWUI
            path, name = await self._file_info(f)
            if not path:
                continue
            if os.path.splitext(name or path)[1].lower() in DOC_EXT:
                continue  # документ -> рідний пошук/екстракція OWUI
            handled.add(f.get("id") or (f.get("file") or {}).get("id"))
            if over:
                parts.append("### Файл: %s\nНе розібрано: користувач перевищив свій ліміт простору (%.0f ГБ). Скажи йому звільнити місце (видалити старі проєкти чи файли) або звернутися до адміністратора." % (name, self.valves.quota_gb))
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "«%s» не розібрано: перевищено ліміт %.0f ГБ" % (name, self.valves.quota_gb), "done": True}})
                continue
            try:
                size_mb = os.path.getsize(path) / 1048576
            except OSError:
                size_mb = 0
            if size_mb > self.valves.max_mb:
                parts.append("### Файл: %s\nНЕ розібрано: %.0f МБ більше за ліміт чату %d МБ. Скажи користувачу, що великі "
                             "докази (до 10 ГБ) треба завантажити через бота%s." % (
                                 name, size_mb, self.valves.max_mb,
                                 (": " + self.valves.big_upload_hint) if self.valves.big_upload_hint else " (кнопка великого завантаження)"))
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {
                        "description": "«%s»: %.0f МБ — завеликий для чату (ліміт %d МБ)" % (name, size_mb, self.valves.max_mb),
                        "done": True}})
                continue
            if __event_emitter__:
                await __event_emitter__({"type": "status", "data": {
                    "description": "Розбираю «%s» в ізольованій пісочниці…" % name, "done": False}})
            ticket = uuid.uuid4().hex[:12]
            t0 = time.time()
            task = asyncio.ensure_future(asyncio.to_thread(self._call, path, ticket, self._who(__user__, __request__, name)))
            while not task.done():
                await asyncio.wait({task}, timeout=self.valves.progress_every_s)
                if not task.done() and __event_emitter__:
                    txt = await asyncio.to_thread(self._progress_text, name, ticket, t0)
                    await __event_emitter__({"type": "status", "data": {"description": txt, "done": False}})
            res = task.result()
            if res.get("ok"):
                block = "### Файл: %s\n%s\n\nСтруктурований зміст (JSON):\n%s" % (
                    name, res.get("report", ""), res.get("context", "")[: self.valves.max_chars_per_file])
                if res.get("encrypted"):
                    block = "(архів збирача, розшифровано автоматично)\n" + block
            else:
                why = {
                    "timeout": "розбір не вклався у 15 хв — файл заскладний для чату, краще через бота",
                    "too_big": "файл більший за ліміт пісочниці",
                    "bomb": "архів розпаковується в надто великий обсяг (захист від архів-бомби): понад 2 ГБ або забагато файлів",
                    "killed": "пісочниці забракло памʼяті на цей файл",
                    "password": "архів під паролем, який не вдалося підібрати автоматично",
                }.get(res.get("error"), res.get("error") or "невідома помилка")
                block = "### Файл: %s\nРозбір не вдався: %s. Скажи це користувачу простими словами, нічого не вигадуй про вміст." % (name, why)
            parts.append(block)
            if __event_emitter__:
                await __event_emitter__({"type": "status", "data": {
                    "description": "Файл «%s» розібрано. Це тимчасовий файл: його буде видалено через %d год. Щоб зберегти — додайте його в джерела проєкту." % (name, self.valves.ttl_hours), "done": True}})

        if handled:
            keepf = lambda lst: [x for x in (lst or []) if not (isinstance(x, dict) and (x.get("id") or (x.get("file") or {}).get("id")) in handled)]
            if isinstance(body.get("files"), list):
                body["files"] = keepf(body["files"])
            md = body.get("metadata")
            if isinstance(md, dict) and isinstance(md.get("files"), list):
                md["files"] = keepf(md["files"])
        # правила про файли — лише коли файли справді є (інакше модель на «привіт» відповідає як форензик)
        if not parts and not files:
            return body
        sys_text = RULES
        if parts:
            sys_text += "\n\nРезультати розбору прикріплених файлів (пісочниця, лише читання):\n\n" + "\n\n".join(parts)
        msgs = body.get("messages") or []
        msgs.insert(0, {"role": "system", "content": sys_text})
        body["messages"] = msgs
        return body
