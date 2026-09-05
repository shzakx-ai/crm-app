"""Database access + schema management with real migration versioning.

Migrations are ordered, numbered files in `migrations/` each exposing
`migrate(conn)`.  A `schema_migrations` table records which versions ran,
so every database — fresh or upgraded from v1/v2/v3.1 — converges to the
same schema without re-running old steps.
"""
import sqlite3
from contextlib import contextmanager
from importlib import import_module

from .config import get_db_path

# Ordered list of migration modules (version 1 is the initial schema).
MIGRATIONS = ["001_init", "002_owner_id", "003_api_bot"]


@contextmanager
def get_db():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _applied_versions(conn) -> set:
    try:
        return {r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    except sqlite3.OperationalError:
        return set()


def _ensure_migrations_table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT DEFAULT (datetime('now'))
        )"""
    )


def migrate_db():
    """Apply pending migrations in order. Safe to call repeatedly.

    Opens its own connection with `PRAGMA foreign_keys=OFF` set *before* any
    transaction begins. This is essential: migrations rebuild tables
    (create-new -> copy -> drop). With foreign_keys on, SQLite would run
    an implicit DELETE on DROP TABLE and fire ON DELETE CASCADE against
    child rows (deals/activities) — silently destroying data during an
    upgrade. PRAGMA foreign_keys is ignored inside a transaction, so it
    must be toggled before the first DML statement.
    """
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=OFF")   # <-- critical: before any DML
        _ensure_migrations_table(conn)
        applied = _applied_versions(conn)
        for name in MIGRATIONS:
            if name in applied:
                continue
            mod = import_module(f"migrations.{name}")
            mod.migrate(conn)
            conn.execute("INSERT INTO schema_migrations (version) VALUES (?)", (name,))
            print(f"🧬 Migration applied: {name}")
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Idempotent full schema bootstrap (new databases)."""
    migrate_db()