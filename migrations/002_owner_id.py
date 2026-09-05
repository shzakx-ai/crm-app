"""v2 — add contacts.owner_id to databases created before row-level ownership.

Only alters legacy tables; fresh DBs get owner_id from 001_init."""


def _column_names(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def migrate(conn):
    cols = _column_names(conn, "contacts")
    if "owner_id" not in cols:
        conn.execute("ALTER TABLE contacts ADD COLUMN owner_id INTEGER NOT NULL DEFAULT 1")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id)")
    # Assign legacy rows to the first admin (unless already a valid owner)
    admin = conn.execute(
        "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
    ).fetchone()
    if admin:
        conn.execute(
            "UPDATE contacts SET owner_id=? WHERE owner_id NOT IN (SELECT id FROM users)",
            (admin["id"],),
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