"""SQLite persistence. Inspection methods are for the trusted local operator only."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY, content TEXT NOT NULL, label TEXT NOT NULL,
                parents TEXT NOT NULL, content_hash TEXT NOT NULL, kind TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY, principal TEXT NOT NULL, label TEXT NOT NULL,
                sources TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS inbox (
                id INTEGER PRIMARY KEY, recipient TEXT NOT NULL, artifact TEXT NOT NULL,
                workflow TEXT NOT NULL, content_hash TEXT NOT NULL,
                UNIQUE(recipient, artifact, workflow));
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY, operation TEXT NOT NULL, resource TEXT NOT NULL,
                workflow TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY, payload TEXT NOT NULL,
                previous_hash TEXT NOT NULL, hash TEXT NOT NULL);
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def audit(db, payload):
        last = db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        previous = last[0] if last else "0" * 64
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(), **payload}
        serialized = canonical(payload)
        cursor = db.execute("INSERT INTO audit(payload,previous_hash,hash) VALUES(?,?,?)",
                            (serialized, previous, digest(previous + serialized)))
        return cursor.lastrowid

    def events(self):
        with self.connection() as db:
            return [{"event_id": r["id"], **json.loads(r["payload"]), "hash": r["hash"],
                     "previous_hash": r["previous_hash"]}
                    for r in db.execute("SELECT * FROM audit ORDER BY id")]

    def verify_audit(self):
        previous = "0" * 64
        with self.connection() as db:
            for r in db.execute("SELECT * FROM audit ORDER BY id"):
                if r["previous_hash"] != previous or r["hash"] != digest(previous + r["payload"]):
                    return False
                previous = r["hash"]
        return True

    def inspect(self, table):
        # Static allowlist: no untrusted SQL identifiers.
        if table not in {"artifacts", "workflows", "inbox", "executions"}:
            raise ValueError("Unknown table")
        with self.connection() as db:
            return [dict(row) for row in db.execute(f"SELECT * FROM {table}")]
