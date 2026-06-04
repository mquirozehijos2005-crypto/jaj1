"""Persistencia ligera en SQLite (watchlist, notas, prefs de usuario)."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_LOCK = threading.RLock()


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        with _LOCK:
            con = sqlite3.connect(self.db_path)
            con.row_factory = sqlite3.Row
            try:
                yield con
                con.commit()
            finally:
                con.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_prefs (
                    user_id INTEGER PRIMARY KEY,
                    lang    TEXT NOT NULL DEFAULT 'es',
                    created REAL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS watchlist (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id   INTEGER NOT NULL,
                    kind      TEXT NOT NULL,           -- domain | ip | hash | url
                    target    TEXT NOT NULL,
                    last_seen TEXT,                    -- snapshot serializado (json)
                    created   REAL DEFAULT (strftime('%s','now')),
                    UNIQUE(user_id, kind, target)
                );

                CREATE TABLE IF NOT EXISTS notes (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title   TEXT NOT NULL,
                    body    BLOB NOT NULL,             -- cifrado AES-GCM
                    salt    BLOB NOT NULL,
                    nonce   BLOB NOT NULL,
                    created REAL DEFAULT (strftime('%s','now'))
                );

                CREATE TABLE IF NOT EXISTS cache (
                    k       TEXT PRIMARY KEY,
                    v       TEXT NOT NULL,
                    expires REAL NOT NULL
                );
                """
            )

    # ---------- prefs ----------
    def get_lang(self, user_id: int, default: str = "es") -> str:
        with self._conn() as c:
            row = c.execute(
                "SELECT lang FROM user_prefs WHERE user_id=?", (user_id,)
            ).fetchone()
            return row["lang"] if row else default

    def set_lang(self, user_id: int, lang: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO user_prefs(user_id, lang) VALUES(?,?) "
                "ON CONFLICT(user_id) DO UPDATE SET lang=excluded.lang",
                (user_id, lang),
            )

    # ---------- watchlist ----------
    def watch_add(self, user_id: int, kind: str, target: str) -> bool:
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO watchlist(user_id, kind, target) VALUES(?,?,?)",
                    (user_id, kind, target),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def watch_remove(self, user_id: int, watch_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM watchlist WHERE id=? AND user_id=?", (watch_id, user_id)
            )
            return cur.rowcount > 0

    def watch_list(self, user_id: int) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, kind, target, last_seen, created "
                "FROM watchlist WHERE user_id=? ORDER BY id",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def watch_all(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, user_id, kind, target, last_seen FROM watchlist"
            ).fetchall()
            return [dict(r) for r in rows]

    def watch_update_snapshot(self, watch_id: int, snapshot: str) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE watchlist SET last_seen=? WHERE id=?", (snapshot, watch_id)
            )

    # ---------- notas cifradas ----------
    def note_save(
        self, user_id: int, title: str, body: bytes, salt: bytes, nonce: bytes
    ) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO notes(user_id, title, body, salt, nonce) VALUES(?,?,?,?,?)",
                (user_id, title, body, salt, nonce),
            )
            return int(cur.lastrowid)

    def note_get(self, user_id: int, note_id: int) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT id, title, body, salt, nonce FROM notes WHERE id=? AND user_id=?",
                (note_id, user_id),
            ).fetchone()
            return dict(row) if row else None

    def note_list(self, user_id: int) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT id, title, created FROM notes WHERE user_id=? ORDER BY id DESC",
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def note_delete(self, user_id: int, note_id: int) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "DELETE FROM notes WHERE id=? AND user_id=?", (note_id, user_id)
            )
            return cur.rowcount > 0

    # ---------- caché ----------
    def cache_get(self, key: str) -> str | None:
        import time

        with self._conn() as c:
            row = c.execute(
                "SELECT v, expires FROM cache WHERE k=?", (key,)
            ).fetchone()
            if row and row["expires"] > time.time():
                return row["v"]
            if row:
                c.execute("DELETE FROM cache WHERE k=?", (key,))
            return None

    def cache_set(self, key: str, value: str, ttl_sec: int) -> None:
        import time

        with self._conn() as c:
            c.execute(
                "INSERT INTO cache(k,v,expires) VALUES(?,?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v, expires=excluded.expires",
                (key, value, time.time() + ttl_sec),
            )
