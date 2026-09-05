"""Test suite for CRM App v3 — session auth, validation, CRUD, security."""
import os
import sys
import tempfile
import pytest
from pathlib import Path

# Ensure project root is importable (CI runs from repo root, tests/ subdir)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Use temp DB for tests
_tmp = tempfile.mkdtemp(prefix="crm_test_")
os.environ["CRM_DB"] = os.path.join(_tmp, "test.db")
os.environ["CRM_ADMIN_USER"] = "testadmin"
os.environ["CRM_ADMIN_PASSWORD"] = "testpass123"
os.environ["CRM_SESSION_SECRET"] = "test-secret-for-tests"
os.environ["CRM_API_TOKEN"] = "test-bearer-token"

from fastapi.testclient import TestClient
from fastapi import HTTPException
import app.main as crm_app_module
from app.main import app
from app import db as crm_db
from app import auth as crm_auth

client = TestClient(app)
crm_app = crm_app_module  # alias (get_db forwarded below) so existing calls keep working
crm_app.get_db = crm_db.get_db


@pytest.fixture(autouse=True)
def _clean_db():
    """Drop all rows + reset AUTOINCREMENT + clear cookies before each test."""
    client.cookies.clear()
    with crm_app.get_db() as db:
        db.execute("DELETE FROM activities")
        db.execute("DELETE FROM deals")
        db.execute("DELETE FROM contacts")
        db.execute("DELETE FROM sqlite_sequence WHERE name IN ('contacts','deals','activities')")
    yield
    with crm_app.get_db() as db:
        db.execute("DELETE FROM activities")
        db.execute("DELETE FROM deals")
        db.execute("DELETE FROM contacts")
        db.execute("DELETE FROM sqlite_sequence WHERE name IN ('contacts','deals','activities')")


# ── Auth tests ────────────────────────────────────────────────────────────
def test_index_redirects_to_login_when_unauthenticated():
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert "/login" in r.headers["location"]


def test_login_success_sets_httponly_cookie():
    r = client.post("/login", data={"username": "testadmin", "password": "testpass123"},
                    follow_redirects=False)
    assert r.status_code == 302
    cookie = r.headers.get("set-cookie", "")
    assert "crm_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie


def test_login_wrong_password_rejected():
    r = client.post("/login", data={"username": "testadmin", "password": "wrong"})
    assert r.status_code == 401


def test_api_blocked_without_auth():
    r = client.get("/api/stats")
    assert r.status_code == 401


def test_api_works_with_session_cookie():
    login = client.post("/login", data={"username": "testadmin", "password": "testpass123"}, follow_redirects=False)
    assert login.status_code == 302  # redirect to / means login succeeded
    assert "crm_session=" in login.headers.get("set-cookie", "")
    r = client.get("/api/stats")
    assert r.status_code == 200
    assert "total_contacts" in r.json()


def test_api_works_with_bearer_token():
    r = client.get("/api/stats", headers={"Authorization": "Bearer test-bearer-token"})
    assert r.status_code == 200


def test_api_rejects_wrong_bearer():
    r = client.get("/api/stats", headers={"Authorization": "Bearer wrong-token"})
    assert r.status_code == 401


def test_no_secret_in_index_html():
    login = client.post("/login", data={"username": "testadmin", "password": "testpass123"})
    r = client.get("/")
    html = r.text
    # The token/session secret must NOT appear in HTML
    assert "test-bearer-token" not in html
    assert "test-secret-for-tests" not in html
    assert "crm_token" not in html


def test_session_cookie_is_signed_and_expiry_valid():
    from app.auth import create_session_token, verify_session_token
    tok = create_session_token()
    assert verify_session_token(tok) is not None  # returns user_id (int) if valid
    # Tampered token rejected
    assert verify_session_token(tok[:-3] + "abc") is None  # tampered → None


# ── Contacts CRUD ─────────────────────────────────────────────────────────
def _login_headers():
    client.post("/login", data={"username": "testadmin", "password": "testpass123"})
    return {}


def test_create_contact():
    _login_headers()
    r = client.post("/api/contacts", json={"first_name": "Ali", "email": "ali@test.com"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["id"] == 1


def test_create_contact_missing_first_name_422():
    _login_headers()
    r = client.post("/api/contacts", json={"email": "x@test.com"})
    assert r.status_code == 422


def test_create_contact_invalid_status_422():
    _login_headers()
    r = client.post("/api/contacts", json={"first_name": "A", "status": "superstar"})
    assert r.status_code == 422


def test_create_contact_invalid_email_422():
    _login_headers()
    r = client.post("/api/contacts", json={"first_name": "A", "email": "not-an-email"})
    assert r.status_code == 422


def test_update_contact_email_validator_works():
    _login_headers()
    client.post("/api/contacts", json={"first_name": "Ali", "email": "ali@test.com"})
    # Create with valid email, then update to invalid → 422 (validator on update)
    r = client.put("/api/contacts/1", json={"email": "bad-email"})
    assert r.status_code == 422


def test_update_contact_not_found_404():
    _login_headers()
    r = client.put("/api/contacts/999", json={"first_name": "X"})
    assert r.status_code == 404


def test_delete_contact_missing_404():
    _login_headers()
    r = client.delete("/api/contacts/999")
    assert r.status_code == 404


def test_delete_contact_ok():
    _login_headers()
    client.post("/api/contacts", json={"first_name": "Ali"})
    r = client.delete("/api/contacts/1")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_limit_bounds_validated():
    _login_headers()
    r = client.get("/api/contacts?limit=999")
    assert r.status_code == 422


# ── Deals CRUD ────────────────────────────────────────────────────────────
def test_create_deal_requires_valid_contact():
    _login_headers()
    r = client.post("/api/deals", json={"contact_id": 999, "title": "Test", "value": 100})
    assert r.status_code == 404


def test_create_deal_and_list():
    _login_headers()
    client.post("/api/contacts", json={"first_name": "Ali"})
    r = client.post("/api/deals", json={"contact_id": 1, "title": "Big Deal", "value": 5000, "stage": "lead"})
    assert r.status_code == 200
    deals = client.get("/api/deals").json()["deals"]
    assert len(deals) == 1
    assert deals[0]["title"] == "Big Deal"
    assert deals[0]["value"] == 5000


def test_delete_deal_missing_404():
    _login_headers()
    r = client.delete("/api/deals/999")
    assert r.status_code == 404


# ── Stats ─────────────────────────────────────────────────────────────────
def test_stats_counts():
    _login_headers()
    client.post("/api/contacts", json={"first_name": "A", "status": "lead"})
    client.post("/api/contacts", json={"first_name": "B", "status": "customer"})
    client.post("/api/contacts", json={"first_name": "C", "status": "customer"})
    client.post("/api/deals", json={"contact_id": 1, "title": "D1", "value": 100, "stage": "won"})
    s = client.get("/api/stats").json()
    assert s["total_contacts"] == 3
    assert s["by_status"]["customer"] == 2
    assert s["won_value"] == 100


# ── Multi-user & roles ────────────────────────────────────────────────────
def test_users_table_seeded_admin():
    with crm_app.get_db() as db:
        row = db.execute("SELECT username, role FROM users WHERE username='testadmin'").fetchone()
        assert row is not None
        assert row["role"] == "admin"


def test_admin_can_create_member_user():
    _login_headers()
    r = client.post("/api/users", json={"username": "sara", "password": "strongpass123", "role": "member"})
    assert r.status_code == 200
    u = client.get("/api/users").json()["users"]
    assert any(x["username"] == "sara" and x["role"] == "member" for x in u)


def test_member_cannot_access_admin_apis():
    _login_headers()
    client.post("/api/users", json={"username": "member1", "password": "strongpass123", "role": "member"})
    client.post("/logout")
    # Login as member
    m = client.post("/login", data={"username": "member1", "password": "strongpass123"}, follow_redirects=False)
    assert m.status_code == 302
    r = client.get("/api/users")
    assert r.status_code == 403  # member cannot list users
    # member can still use normal APIs
    r2 = client.get("/api/contacts")
    assert r2.status_code == 200


def test_duplicate_username_409():
    _login_headers()
    client.post("/api/users", json={"username": "dup", "password": "strongpass123", "role": "member"})
    r = client.post("/api/users", json={"username": "dup", "password": "anotherpass123", "role": "member"})
    assert r.status_code == 409


# ── Rate limiting ─────────────────────────────────────────────────────────
def test_login_rate_limit_blocks_after_5():
    # Clear attempts
    crm_auth._login_attempts.clear()
    client.cookies.clear()
    for _ in range(5):
        r = client.post("/login", data={"username": "admin", "password": "wrongpass"}, follow_redirects=False)
        assert r.status_code == 401
    # 6th attempt now rate-limited
    r = client.post("/login", data={"username": "admin", "password": "wrongpass"}, follow_redirects=False)
    assert r.status_code == 429


# ── Ownership isolation (member can't see/modify admin data) ─────────────
def _create_member(name):
    _login_headers()
    client.post("/api/users", json={"username": name, "password": "strongpass123", "role": "member"})
    client.post("/logout")
    m = client.post("/login", data={"username": name, "password": "strongpass123"}, follow_redirects=False)
    assert m.status_code == 302


def test_owner_isolation_contacts():
    # Admin creates a contact
    _login_headers()
    r = client.post("/api/contacts", json={"first_name": "AdminContact"})
    assert r.status_code == 200
    admin_cid = r.json()["id"]
    client.post("/logout")

    # Member logs in — should NOT see admin's contact
    _create_member("isomember")
    contacts = client.get("/api/contacts").json()["contacts"]
    assert all(c["id"] != admin_cid for c in contacts)
    # Member cannot read it directly either
    assert client.get(f"/api/contacts/{admin_cid}").status_code == 404
    # Member cannot update/delete it
    assert client.put(f"/api/contacts/{admin_cid}", json={"first_name": "Hacked"}).status_code == 404
    assert client.delete(f"/api/contacts/{admin_cid}").status_code == 404


def test_owner_gets_own_contacts():
    _create_member("ownermember")
    r = client.post("/api/contacts", json={"first_name": "Mine"})
    assert r.status_code == 200
    mine = r.json()["id"]
    contacts = client.get("/api/contacts").json()["contacts"]
    assert any(c["id"] == mine for c in contacts)
    # Member can read/update/delete own contact
    assert client.get(f"/api/contacts/{mine}").status_code == 200
    assert client.put(f"/api/contacts/{mine}", json={"first_name": "Mine2"}).status_code == 200
    assert client.delete(f"/api/contacts/{mine}").status_code == 200


def test_owner_isolation_deals_and_stats():
    # Admin contact + deal
    _login_headers()
    rc = client.post("/api/contacts", json={"first_name": "AdminDealOwner"}).json()
    admin_cid = rc["id"]
    client.post("/api/deals", json={"contact_id": admin_cid, "title": "AdminSecret", "value": 9999})
    client.post("/logout")

    # Member: count only own data in stats, cannot attach deal to admin contact
    _create_member("dealmember")
    assert client.get("/api/stats").json()["total_contacts"] == 0
    r = client.post("/api/deals", json={"contact_id": admin_cid, "title": "Steal", "value": 1})
    assert r.status_code == 404  # cannot create deal on someone else's contact
    deals = client.get("/api/deals").json()["deals"]
    assert all(d["title"] != "AdminSecret" for d in deals)


# ── Migration: v3.1 DB without owner_id must upgrade safely ──────────────
def test_migrate_legacy_db_adds_owner_column():
    import sqlite3
    # Build a legacy v3.1 database WITHOUT owner_id (file on disk, not env-swapped)
    legacy = Path(_tmp) / "legacy31.db"
    if legacy.exists():
        legacy.unlink()
    conn = sqlite3.connect(legacy)
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE, password_hash TEXT,
            role TEXT DEFAULT 'member', created_at TEXT
        );
        INSERT INTO users (username, password_hash, role) VALUES ('legacyadmin', 'x', 'admin');
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT, last_name TEXT, email TEXT,
            company TEXT, phone TEXT, status TEXT DEFAULT 'new',
            created_at TEXT, updated_at TEXT
        );
        INSERT INTO contacts (first_name, last_name) VALUES ('Old', 'Contact');
        CREATE TABLE deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER, title TEXT, value REAL,
            stage TEXT DEFAULT 'lead', expected_close TEXT, notes TEXT,
            created_at TEXT, updated_at TEXT
        );
        CREATE TABLE activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER, deal_id INTEGER, type TEXT DEFAULT 'note',
            subject TEXT, body TEXT, done INTEGER DEFAULT 0, due_date TEXT,
            created_at TEXT
        );
    """)
    conn.commit(); conn.close()

    # Point the app at the legacy DB, run migrations directly (same versioning)
    on = os.environ.get("CRM_DB")
    try:
        os.environ["CRM_DB"] = str(legacy)
        crm_db.migrate_db()
        conn = sqlite3.connect(legacy)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(contacts)").fetchall()}
        assert "owner_id" in cols
        # Backfilled owner = legacy admin id (id 1)
        owner = conn.execute("SELECT owner_id FROM contacts LIMIT 1").fetchone()[0]
        assert owner == 1
        conn.close()
    finally:
        os.environ["CRM_DB"] = on


def test_migrate_idempotent_second_run_noop():
    """Running migrate_db twice on the same DB must not duplicate/break anything."""
    import sqlite3
    import os as _os
    on = os.environ.get("CRM_DB")
    db_file = str(Path(_tmp) / "legacy31.idem.db")
    if _os.path.exists(db_file):
        _os.remove(db_file)
    try:
        os.environ["CRM_DB"] = db_file
        # Build legacy DB
        conn = sqlite3.connect(os.environ["CRM_DB"])
        conn.executescript("""
            CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'member', created_at TEXT);
            INSERT INTO users (username, password_hash, role) VALUES ('idemadmin', 'x', 'admin');
            CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT, last_name TEXT DEFAULT '', status TEXT DEFAULT 'lead', created_at TEXT, updated_at TEXT);
            CREATE TABLE deals (id INTEGER PRIMARY KEY AUTOINCREMENT, contact_id INTEGER, title TEXT, value REAL, stage TEXT DEFAULT 'lead', expected_close TEXT, notes TEXT, created_at TEXT, updated_at TEXT);
            CREATE TABLE activities (id INTEGER PRIMARY KEY AUTOINCREMENT, contact_id INTEGER, deal_id INTEGER, type TEXT DEFAULT 'note', subject TEXT, body TEXT, done INTEGER DEFAULT 0, due_date TEXT, created_at TEXT);
            INSERT INTO contacts (first_name) VALUES ('Keep');
        """)
        conn.commit(); conn.close()
        crm_db.migrate_db()
        crm_db.migrate_db()  # second run must be a no-op
        conn = sqlite3.connect(os.environ["CRM_DB"])
        versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()]
        assert versions == ["001_init", "002_owner_id", "003_api_bot"]
        rows = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        assert rows == 1
        conn.close()
    finally:
        os.environ["CRM_DB"] = on


# ── Bearer API client creates contacts with valid owner (FK-safe) ────────
def test_bearer_creates_contact_with_valid_owner():
    # Bearer client is admin role, owner must be an existing users.id (api-bot)
    r = client.post(
        "/api/contacts",
        json={"first_name": "BotContact"},
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert r.status_code == 200
    cid = r.json()["id"]
    with crm_app.get_db() as db:
        owner = db.execute("SELECT owner_id FROM contacts WHERE id=?", (cid,)).fetchone()[0]
        bot = db.execute("SELECT id FROM users WHERE username='api-bot'").fetchone()
        assert bot is not None
        assert owner == bot["id"]


# ── Deleting a user with data is refused (no cascade data loss) ──────────
def test_delete_user_with_data_refused():
    _login_headers()
    client.post("/api/users", json={"username": "datamember", "password": "strongpass123", "role": "member"})
    client.post("/logout")
    _create_member("datamember")
    client.post("/api/contacts", json={"first_name": "Their Data"})
    client.post("/logout")
    _login_headers()
    # datamember is now the last created user; find real id instead of hardcoding 3
    with crm_app.get_db() as db:
        uid = db.execute("SELECT id FROM users WHERE username='datamember'").fetchone()[0]
    r = client.delete(f"/api/users/{uid}")
    assert r.status_code == 409  # has data -> refused


def test_delete_user_without_data_succeeds():
    _login_headers()
    client.post("/api/users", json={"username": "emptymember", "password": "strongpass123", "role": "member"})
    with crm_app.get_db() as db:
        uid = db.execute("SELECT id FROM users WHERE username='emptymember'").fetchone()[0]
    r = client.delete(f"/api/users/{uid}")
    assert r.status_code == 200


# ── total respects search & status filters ───────────────────────────────
def test_total_respects_filters():
    _login_headers()
    client.post("/api/contacts", json={"first_name": "Anna", "email": "anna@x.com", "status": "prospect"})
    client.post("/api/contacts", json={"first_name": "Bob", "email": "bob@x.com", "status": "lead"})
    client.post("/api/contacts", json={"first_name": "Cara", "email": "cara@x.com", "status": "won"})
    r = client.get("/api/contacts?search=anna")
    assert r.json()["total"] == 1
    r = client.get("/api/contacts?status=prospect")
    assert r.json()["total"] == 1
    r = client.get("/api/contacts?status=lead")
    assert r.json()["total"] == 1
    r = client.get("/api/contacts?status=lead&search=bob")
    assert r.json()["total"] == 1
    r = client.get("/api/contacts?status=lead&search=anna")
    assert r.json()["total"] == 0


# ── assert_owned_contact works with an alias (latent bug guard) ───────────
def test_owned_scope_with_alias():
    from app.services.ownership import assert_owned_contact
    _login_headers()
    r = client.post("/api/contacts", json={"first_name": "Aliased"})
    cid = r.json()["id"]
    with crm_app.get_db() as db:
        # admin passes, member without scope would 404; alias must not break SQL
        admin = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        user = dict(admin)
        user["role"] = "admin"
        assert_owned_contact(db, user, cid, alias="c")  # must not raise
        member = {"id": admin["id"] + 999, "role": "member"}
        try:
            assert_owned_contact(db, member, cid, alias="c")
            assert False, "member with wrong owner should raise"
        except HTTPException as e:
            assert e.status_code == 404


# ── legacy upgrade produces an FK constraint identical to fresh ───────────
def test_legacy_upgrade_has_owner_fk():
    import sqlite3
    legacy = Path(tempfile.mkdtemp()) / "legacy_fk.db"
    conn = sqlite3.connect(legacy)
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'member', created_at TEXT);
        INSERT INTO users (username, password_hash, role) VALUES ('oldadmin','x','admin');
        CREATE TABLE contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, first_name TEXT NOT NULL,
            last_name TEXT NOT NULL DEFAULT '', email TEXT DEFAULT '', phone TEXT DEFAULT '',
            company TEXT DEFAULT '', position TEXT DEFAULT '', status TEXT DEFAULT 'lead',
            source TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT, updated_at TEXT
        );
        INSERT INTO contacts (first_name) VALUES ('Legacy');
    """)
    conn.commit(); conn.close()
    on = os.environ.get("CRM_DB")
    try:
        os.environ["CRM_DB"] = str(legacy)
        crm_db.migrate_db()
        conn = sqlite3.connect(legacy)
        fks = conn.execute("PRAGMA foreign_key_list(contacts)").fetchall()
        assert any(row[2] == "users" and row[3] == "owner_id" for row in fks), fks
        owner = conn.execute("SELECT owner_id FROM contacts WHERE first_name='Legacy'").fetchone()[0]
        conn.close()
        assert owner == 1
    finally:
        os.environ["CRM_DB"] = on