"""Database helpers — thin wrappers over psycopg2."""
import psycopg2
from datetime import datetime, timezone
from core.config import PG_DSN


def q(sql, params=()):
    """Execute SQL without returning results (DDL, INSERT, UPDATE)."""
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql, params)


def table_exists(name: str) -> bool:
    with psycopg2.connect(PG_DSN) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
                "WHERE table_schema='public' AND table_name=%s)",
                (name,),
            )
            return cur.fetchone()[0]


def rowdict(cur) -> dict | None:
    """Fetch one row as {column: value} dict."""
    row = cur.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))


def fetchall_dicts(cur) -> list[dict]:
    """Fetch all rows as list of {column: value} dicts."""
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def connect():
    """Return a new psycopg2 connection."""
    return psycopg2.connect(PG_DSN)


def _parse_ts(val):
    """Parse a timestamp value (string, int epoch, or datetime) to UTC datetime."""
    if not val:
        return None
    s = str(val).strip()
    if not s:
        return None
    if s.lstrip('-').isdigit():
        try:
            n = int(s)
            if n > 13_000_000_000_000_000:
                n = (n // 1_000_000) - 11644473600
            elif n > 9_999_999_999:
                n = n // 1000
            return datetime.fromtimestamp(n, tz=timezone.utc)
        except Exception:
            pass
    s = s.replace('T', ' ')
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    for fmt in [None, '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%m/%d/%Y %H:%M:%S', '%d.%m.%Y %H:%M:%S']:
        try:
            if fmt is None:
                dt = datetime.fromisoformat(s)
            else:
                dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return None
