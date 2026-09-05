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
import app as crm_app

client = TestClient(crm_app.app)


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
    from app import create_session_token, verify_session_token
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
    import app as crm_app
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
    import app as crm_app
    crm_app._login_attempts.clear()
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