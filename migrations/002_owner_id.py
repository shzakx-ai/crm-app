"""v2 — add contacts.owner_id to databases created before row-level ownership.

Re-builds the contacts table so the resulting schema is *identical* to a
fresh install (same columns, same FOREIGN KEY constraint). SQLite cannot add
a REFERENCES clause with ALTER TABLE, so we use the standard
create-new -> copy -> drop -> rename dance.
"""


def _column_names(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def migrate(conn):
    # Render the column list from the *current* table so we preserve any
    # extra columns a legacy install may have added.
    old_cols = _column_names(conn, "contacts")
    if "id" not in old_cols:
        raise RuntimeError("contacts table missing id column; cannot migrate")

    keep = [c for c in ("id", "owner_id", "first_name", "last_name", "email", "phone",
                        "company", "position", "status", "source", "notes",
                        "created_at", "updated_at") if c != "owner_id"]
    # Union: columns that exist now plus the ones our schema expects.
    all_cols = list(dict.fromkeys(keep + ["owner_id"] + [c for c in old_cols if c not in keep]))

    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        # Rebuild with the final schema (owner_id + FK).
        col_defs = [f'"{c}"' for c in all_cols]
        # contacts_new starts with owner_id NOT NULL DEFAULT 1 FK -> users(id)
        create = f"""
        CREATE TABLE contacts_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL DEFAULT 1 REFERENCES users(id) ON DELETE CASCADE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL DEFAULT '',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            company TEXT DEFAULT '',
            position TEXT DEFAULT '',
            status TEXT DEFAULT 'lead',
            source TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        """
        conn.execute(create)
        cols_sql = ", ".join('"' + c + '"' for c in all_cols if c != "owner_id")
        target = ", ".join('"' + c + '"' for c in all_cols)
        conn.execute(
            "INSERT INTO contacts_new (" + target + ") SELECT " + cols_sql + ", 1 FROM contacts"
        )
        conn.execute("DROP TABLE contacts")
        conn.execute("ALTER TABLE contacts_new RENAME TO contacts")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id)")
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys=ON")

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
        return col in _column_names(conn, table)

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