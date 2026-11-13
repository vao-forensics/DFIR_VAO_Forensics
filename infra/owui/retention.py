#!/usr/bin/env python3
# DFIR Open WebUI retention worker.
# Deletes uploaded files older than TTL_HOURS using Open WebUI's OWN deletion
# cascade (DB row + on-disk file + vector embeddings + KB links), so nothing is
# left behind. Privacy: logs counts and file-id prefixes only, never filenames
# or content. DRY_RUN=1 -> report only, delete nothing.
import os, sys, time, asyncio, datetime, logging

TTL_HOURS = float(os.environ.get("RETENTION_TTL_HOURS", "24"))
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
LOG_PATH = os.environ.get("RETENTION_LOG", "/app/backend/data/retention.log")

logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("retention")


def _ts(f):
    v = getattr(f, "created_at", None) or 0
    # created_at may be epoch seconds (int) or datetime
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return v.timestamp()
    except Exception:
        return 0.0


async def main():
    from open_webui.internal.db import AsyncSessionLocal
    from open_webui.models.files import Files
    from open_webui.models.knowledge import Knowledges
    from open_webui.storage.provider import Storage
    from open_webui.retrieval.vector.async_client import ASYNC_VECTOR_DB_CLIENT

    cutoff = time.time() - TTL_HOURS * 3600
    async with AsyncSessionLocal() as db:
        files = await Files.get_files(db=db)
        old = [f for f in files if _ts(f) and _ts(f) < cutoff]
        log.info("scan: total=%d old(>%.0fh)=%d dry_run=%s", len(files), TTL_HOURS, len(old), DRY_RUN)
        print("total=%d old=%d dry_run=%s" % (len(files), len(old), DRY_RUN))
        deleted = failed = 0
        # файли проєктів і баз знань («джерела») не видаляються ніколи: лише тимчасові файли з чату
        import sqlite3 as _sq
        _c = _sq.connect("/app/backend/data/webui.db")
        keep = {r[0] for r in _c.execute("select file_id from knowledge_file")}
        for (_d,) in _c.execute("select coalesce(data,'') || coalesce(items,'') from folder"):
            for _f in files:
                if _f.id in _d:
                    keep.add(_f.id)
        _c.close()
        # deleted-chat files: файли чату, який користувач видалив, ідуть одразу (не чекаючи 24 год),
        # якщо вони не в проєкті/знаннях і не прив'язані до іншого живого чату
        _c2 = _sq.connect("/app/backend/data/webui.db")
        orphan = {r[0] for r in _c2.execute("select file_id from chat_file where chat_id not in (select id from chat)")}
        live = {r[0] for r in _c2.execute("select file_id from chat_file where chat_id in (select id from chat)")}
        gone = orphan - live - keep
        if not DRY_RUN:
            _c2.execute("delete from chat_file where chat_id not in (select id from chat)"); _c2.commit()
        _c2.close()
        have = {f.id for f in old}
        old += [f for f in files if f.id in gone and f.id not in have]
        print("deleted-chat files=%d" % len(gone))
        kept = [f for f in old if f.id in keep]
        old = [f for f in old if f.id not in keep]
        print("kept(project/knowledge)=%d" % len(kept))
        for f in old:
            fid = f.id
            age_h = (time.time() - _ts(f)) / 3600.0
            if DRY_RUN:
                print("WOULD delete %s… age=%.1fh" % (fid[:8], age_h))
                continue
            try:
                knowledges = await Knowledges.get_knowledges_by_file_id(fid, db=db)
                for k in knowledges:
                    await Knowledges.remove_file_from_knowledge_by_id(k.id, fid, db=db)
                    try:
                        await ASYNC_VECTOR_DB_CLIENT.delete(collection_name=k.id, filter={"file_id": fid})
                        if f.hash:
                            await ASYNC_VECTOR_DB_CLIENT.delete(collection_name=k.id, filter={"hash": f.hash})
                    except Exception as e:
                        log.info("kb-embed cleanup %s… skip: %s", k.id[:8], e)
                ok = await Files.delete_file_by_id(fid, db=db)
                if ok:
                    try:
                        Storage.delete_file(f.path)
                    except Exception as e:
                        log.info("storage del %s… : %s", fid[:8], e)
                    try:
                        await ASYNC_VECTOR_DB_CLIENT.delete(collection_name="file-%s" % fid)
                    except Exception as e:
                        log.info("vector del %s… : %s", fid[:8], e)
                    deleted += 1
                    log.info("deleted %s… age=%.1fh", fid[:8], age_h)
                else:
                    failed += 1
            except Exception as e:
                failed += 1
                log.exception("delete failed %s…: %s", fid[:8], e)
        if not DRY_RUN:
            log.info("done: deleted=%d failed=%d", deleted, failed)
            print("deleted=%d failed=%d" % (deleted, failed))


if __name__ == "__main__":
    asyncio.run(main())
