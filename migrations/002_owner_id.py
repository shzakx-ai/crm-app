"""v2 — add contacts.owner_id to databases created before row-level ownership.

Re-builds the contacts table so the resulting schema is *identical* to a
fresh install (same columns, same FOREIGN KEY constraint). SQLite cannot add
a REFERENCES clause with ALTER TABLE, so we use the standard
create-new -> copy -> drop -> rename dance.
"""


def _column_info(conn, table: str) -> list:
    """Return [(name, type, notnull, default)] for each column of `table`."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [(r[1], r[2] or "TEXT", r[3], r[4]) for r in rows]


def migrate(conn):
    # Render the column list from the *current* table so we preserve any
    # extra columns a legacy install may have added.
    old_info = _column_info(conn, "contacts")
    old_cols = {name for name, _t, _n, _d in old_info}
    if "id" not in old_cols:
        raise RuntimeError("contacts table missing id column; cannot migrate")

    # Canonical column definitions (fresh-install parity, with constraint).
    canonical = {
        "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
        "owner_id": "INTEGER NOT NULL DEFAULT 1 REFERENCES users(id) ON DELETE CASCADE",
        "first_name": "TEXT NOT NULL",
        "last_name": "TEXT NOT NULL DEFAULT ''",
        "email": "TEXT DEFAULT ''",
        "phone": "TEXT DEFAULT ''",
        "company": "TEXT DEFAULT ''",
        "position": "TEXT DEFAULT ''",
        "status": "TEXT DEFAULT 'lead' CHECK(status IN ('lead','prospect','customer','inactive','new','won','lost'))",
        "source": "TEXT DEFAULT ''",
        "notes": "TEXT DEFAULT ''",
        "created_at": "TEXT DEFAULT (datetime('now'))",
        "updated_at": "TEXT DEFAULT (datetime('now'))",
    }
    # Non-canonical columns that exist in the legacy table are preserved with
    # their original SQLite type/constraints (so nothing introduced by the
    # upgrade is lost).
    extra_defs = {
        name: f"{name} {typ}{' NOT NULL' if notnull else ''}"
        for name, typ, notnull, _d in old_info
        if name not in canonical and name != "owner_id"
    }
    all_defs = {**canonical, **extra_defs}
    order = ["id", "owner_id", "first_name", "last_name", "email", "phone",
             "company", "position", "status", "source", "notes",
             "created_at", "updated_at"] + [c for c in old_cols if c not in canonical and c != "owner_id"]
    cols_defs = ",\n            ".join(f"{name} {all_defs[name]}" for name in order)

    # NOTE: foreign_keys is already OFF for this connection (app.db.migrate_db
    # disables it before any transaction), so the DROP below cannot fire
    # ON DELETE CASCADE against deals/activities. Run migrations only via
    # the runner — never on a live API connection.
    try:
        # Rebuild with the final schema (owner_id + FK), preserving any extra
        # legacy columns the original database carried.
        create = f"CREATE TABLE contacts_new (\n            {cols_defs}\n        );"
        conn.execute(create)
        # Copy only columns that actually exist in the source table, plus the
        # new owner_id (placeholder 1). Columns that are new to this migration
        # (last_name, email, ...) are NOT selected — because SELECT "last_name"
        # on a source that lacks that column would yield the literal string
        # 'last_name' instead of the DEFAULT. Omitting them lets SQLite apply
        # the table DEFAULTs from the CREATE above.
        ins = [c for c in order if c in old_cols or c == "owner_id"]
        sel_items = ["1" if c == "owner_id" else f'"{c}"' for c in ins]
        target = ", ".join('"' + c + '"' for c in ins)
        conn.execute(
            f"INSERT INTO contacts_new ({target}) SELECT {', '.join(sel_items)} FROM contacts"
        )
        conn.execute("DROP TABLE contacts")
        conn.execute("ALTER TABLE contacts_new RENAME TO contacts")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id)")
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    # Assign legacy rows to the first admin (unless already a valid owner)
    admin = conn.execute(
        "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
    ).fetchone()
    if admin and admin[0]:
        conn.execute(
            "UPDATE contacts SET owner_id=? WHERE owner_id NOT IN (SELECT id FROM users)",
            (admin[0],),
        )

    # Indexes on columns that actually exist (safe against partial legacy schemas)
    def _has(table: str, col: str) -> bool:
        return col in {name for name, _t, _n, _d in _column_info(conn, table)}

    if _has("contacts", "status"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status)")
    if _has("contacts", "company"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company)")
    if _has("deals", "stage"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage)")
    if _has("deals", "contact_id"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id)")
    if _has("activities", "contact_id"):
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id)")