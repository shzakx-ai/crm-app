#!/usr/bin/env python3
"""
CRM App v3 — Session-based auth (HttpOnly cookie), no secrets in HTML
FastAPI + SQLite + Pydantic. Docker-ready.

Security model:
  - /login page (username/password) sets an HttpOnly, SameSite=Lax session cookie
  - session cookie is HMAC-signed (stdlib only) with an expiry timestamp
  - the secret never reaches the browser/HTML/JS
  - optional CRM_API_TOKEN still accepted as Bearer for external API clients
"""
import os
import sqlite3
import hmac
import hashlib
import secrets
import time
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request, Depends, Form, Cookie, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any

# ── Config (from env — never hardcoded) ───────────────────────────────────
DB_PATH = os.environ.get("CRM_DB", "crm.db")
ADMIN_USER = os.environ.get("CRM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("CRM_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
ADMIN_ROLE = "admin"
if not os.environ.get("CRM_ADMIN_PASSWORD"):
    print(f"⚠️  CRM_ADMIN_PASSWORD not set — generated admin password: {ADMIN_PASSWORD}")
    print(f"    Set CRM_ADMIN_PASSWORD in docker-compose/env for persistence.")
SESSION_SECRET = os.environ.get("CRM_SESSION_SECRET") or secrets.token_urlsafe(24)
# Optional: Bearer token for external API clients (not used by the web UI)
API_TOKEN = os.environ.get("CRM_API_TOKEN") or None
if API_TOKEN:
    print("✅ CRM_API_TOKEN enabled for external API clients (Bearer).")

SESSION_TTL = 12 * 3600  # 12 hours
SESSION_COOKIE = "crm_session"

# ── Session helpers (stdlib HMAC — no external deps) ──────────────────────
def _sign(msg: str, secret: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()

def create_session_token(user_id: int = None) -> str:
    expires = int(time.time()) + SESSION_TTL
    uid = user_id if user_id is not None else 0
    payload = f"{expires}.{uid}"
    return f"{payload}.{_sign(payload, SESSION_SECRET)}"

def verify_session_token(token: str) -> Optional[int]:
    """Return user_id if valid, None otherwise."""
    try:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            return None
        payload, sig = parts
        if not hmac.compare_digest(_sign(payload, SESSION_SECRET), sig):
            return None
        exp_s, uid_s = payload.rsplit(".", 1)
        if int(exp_s) < time.time():
            return None
        return int(uid_s)
    except Exception:
        return None

def _user_by_id(uid: int):
    with get_db() as db:
        return db.execute("SELECT id, username, role FROM users WHERE id=?", (uid,)).fetchone()

def _user_by_username(username: str):
    with get_db() as db:
        return db.execute("SELECT id, username, password_hash, role FROM users WHERE username=?", (username,)).fetchone()

async def require_auth(request: Request) -> dict:
    """Accept session cookie OR optional Bearer token. Returns user dict (or api-client pseudo-user)."""
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie:
        uid = verify_session_token(cookie)
        if uid is not None:
            user = _user_by_id(uid)
            if user:
                return {"id": user["id"], "username": user["username"], "role": user["role"], "method": "session"}
    auth = request.headers.get("Authorization", "")
    if API_TOKEN and auth.startswith("Bearer "):
        supplied = auth[7:]
        if hmac.compare_digest(supplied, API_TOKEN):
            return {"id": 0, "username": "api-client", "role": "admin", "method": "bearer"}
    raise HTTPException(status_code=401, detail="Authentication required")

def require_admin(user: dict = Depends(require_auth)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user

# ── App ───────────────────────────────────────────────────────────────────
app = FastAPI(title="CRM App", version="3.0.0", docs_url="/docs")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── Pydantic Models ───────────────────────────────────────────────────────
def _validate_email(cls, v):
    if v is None or v == "":
        return v
    if "@" not in v or "." not in v.split("@")[-1]:
        raise ValueError(f"Invalid email address: {v}")
    return v

class ContactBase(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="", max_length=50)
    email: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: str = Field(default="lead", pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _validate_email(cls, v)

class ContactCreate(ContactBase):
    pass

class ContactUpdate(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    email: Optional[str] = Field(default=None, max_length=100)
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: Optional[str] = Field(default=None, pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

    @field_validator("email")
    @classmethod
    def email_valid(cls, v):
        return _validate_email(cls, v)

class DealCreate(BaseModel):
    contact_id: int = Field(..., ge=1)
    title: str = Field(..., min_length=1, max_length=200)
    value: float = Field(default=0, ge=0)
    stage: str = Field(default="lead", pattern=r"^(lead|qualified|proposal|negotiation|won|lost)$")
    expected_close: Optional[str] = Field(default=None, max_length=50)
    notes: Optional[str] = Field(default=None, max_length=500)

class DealUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    value: Optional[float] = Field(default=None, ge=0)
    stage: Optional[str] = Field(default=None, pattern=r"^(lead|qualified|proposal|negotiation|won|lost)$")
    expected_close: Optional[str] = Field(default=None, max_length=50)
    notes: Optional[str] = Field(default=None, max_length=500)

class ActivityCreate(BaseModel):
    contact_id: int = Field(..., ge=1)
    deal_id: Optional[int] = None
    type: str = Field(default="note", pattern=r"^(note|call|email|meeting|task)$")
    subject: Optional[str] = Field(default=None, max_length=200)
    body: Optional[str] = Field(default=None, max_length=1000)
    due_date: Optional[str] = Field(default=None, max_length=50)

# ── Password hashing (stdlib, PBKDF2) ─────────────────────────────────────
def hash_password(password: str, salt: str | None = None) -> str:
    """PBKDF2-HMAC-SHA256 with per-user salt. Format: pbkdf2$iter$salt$hash"""
    if salt is None:
        salt = secrets.token_hex(16)
    iterations = 260_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${salt}${dk.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt, expected = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iter_s))
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False

# ── Database ──────────────────────────────────────────────────────────────
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('admin','member')),
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL DEFAULT '',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            company TEXT DEFAULT '',
            position TEXT DEFAULT '',
            status TEXT DEFAULT 'lead' CHECK(status IN ('lead','prospect','customer','inactive')),
            source TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS deals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            value REAL DEFAULT 0,
            currency TEXT DEFAULT 'EUR',
            stage TEXT DEFAULT 'lead' CHECK(stage IN ('lead','qualified','proposal','negotiation','won','lost')),
            expected_close TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL,
            deal_id INTEGER,
            type TEXT DEFAULT 'note' CHECK(type IN ('note','call','email','meeting','task')),
            subject TEXT DEFAULT '',
            body TEXT DEFAULT '',
            done INTEGER DEFAULT 0,
            due_date TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);
        CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company);
        CREATE INDEX IF NOT EXISTS idx_deals_stage ON deals(stage);
        CREATE INDEX IF NOT EXISTS idx_deals_contact ON deals(contact_id);
        CREATE INDEX IF NOT EXISTS idx_activities_contact ON activities(contact_id);
        """)

init_db()

def seed_admin():
    """Insert the env-configured admin if not present."""
    with get_db() as db:
        exists = db.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (ADMIN_USER, hash_password(ADMIN_PASSWORD), ADMIN_ROLE),
            )
            print(f"✅ Seeded admin user: {ADMIN_USER} (role=admin)")

seed_admin()

# ── Login rate limiting (in-memory, per-IP) ──────────────────────────────
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 15 * 60  # 15 minutes
_login_attempts: Dict[str, list] = {}  # ip -> [timestamps]

def _check_login_rate_limit(ip: str):
    now = time.time()
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        wait = int(LOGIN_WINDOW - (now - attempts[0]))
        raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {max(1, wait // 60)} min.")
    _login_attempts[ip].append(now)
    return True

def _login_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# ── Auth routes ───────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Already authed? bounce to /
    if request.cookies.get(SESSION_COOKIE) and verify_session_token(request.cookies.get(SESSION_COOKIE, "")) is not None:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {})

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = _user_by_username(username)
    if not user or not verify_password(password, user["password_hash"]):
        ip = _login_ip(request)
        _check_login_rate_limit(ip)
        raise HTTPException(status_code=401, detail="Invalid credentials or account locked")
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        SESSION_COOKIE,
        create_session_token(user_id=user["id"]),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
        secure=os.environ.get("CRM_COOKIE_SECURE", "").lower() in ("1", "true"),
        path="/",
    )
    return resp

@app.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def me(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie:
        uid = verify_session_token(cookie)
        if uid is not None:
            user = _user_by_id(uid)
            if user:
                return {"authenticated": True, "user": user["username"], "role": user["role"], "method": "session"}
    auth = request.headers.get("Authorization", "")
    if API_TOKEN and auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], API_TOKEN):
        return {"authenticated": True, "user": "api-client", "role": "admin", "method": "bearer"}
    return JSONResponse({"authenticated": False}, status_code=401)

# ── API: Users (admin only) ──────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="member", pattern=r"^(admin|member)$")

@app.get("/api/users", dependencies=[Depends(require_admin)])
async def list_users():
    with get_db() as db:
        rows = [dict(r) for r in db.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()]
        return {"users": rows}

@app.post("/api/users", dependencies=[Depends(require_admin)])
async def create_user(u: UserCreate):
    with get_db() as db:
        exists = db.execute("SELECT id FROM users WHERE username=?", (u.username,)).fetchone()
        if exists:
            raise HTTPException(409, "Username already exists")
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (u.username, hash_password(u.password), u.role),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.delete("/api/users/{uid}", dependencies=[Depends(require_admin)])
async def delete_user(uid: int, auth: dict = Depends(require_auth)):
    if uid == auth["id"]:
        raise HTTPException(400, "Cannot delete your own account")
    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        return {"ok": True, "deleted_id": uid}

# ── API: Contacts ─────────────────────────────────────────────────────────
@app.get("/api/contacts")
async def list_contacts(
    search: str = "",
    status: str = "",
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0, le=10000),
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        q = "SELECT * FROM contacts WHERE 1=1"
        params = []
        if search:
            q += " AND (first_name||' '||last_name LIKE ? OR email LIKE ? OR company LIKE ?)"
            s = f"%{search}%"
            params.extend([s, s, s])
        if status:
            q += " AND status = ?"
            params.append(status)
        q += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = [dict(r) for r in db.execute(q, params).fetchall()]
        total = db.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        return {"contacts": rows, "total": total}

@app.post("/api/contacts")
async def create_contact(
    c: ContactCreate,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO contacts (first_name,last_name,email,phone,company,position,status,source,notes)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (c.first_name, c.last_name, c.email, c.phone, c.company, c.position, c.status, c.source, c.notes),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.get("/api/contacts/{cid}")
async def get_contact(
    cid: int,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        row = db.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        deals = [dict(r) for r in db.execute("SELECT * FROM deals WHERE contact_id=? ORDER BY created_at DESC", (cid,)).fetchall()]
        activities = [dict(r) for r in db.execute("SELECT * FROM activities WHERE contact_id=? ORDER BY created_at DESC LIMIT 50", (cid,)).fetchall()]
        return {"contact": dict(row), "deals": deals, "activities": activities}

@app.put("/api/contacts/{cid}")
async def update_contact(
    cid: int,
    c: ContactUpdate,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        row = db.execute("SELECT id FROM contacts WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        data = c.model_dump(exclude_unset=True)
        if not data:
            raise HTTPException(400, "No fields to update")
        sets = [f"{k}=?" for k in data]
        params = list(data.values()) + [cid]
        db.execute(f"UPDATE contacts SET {','.join(sets)},updated_at=datetime('now') WHERE id=?", params)
        updated = db.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
        return {"ok": True, "contact": dict(updated)}

@app.delete("/api/contacts/{cid}")
async def delete_contact(
    cid: int,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        row = db.execute("SELECT id FROM contacts WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        db.execute("DELETE FROM contacts WHERE id=?", (cid,))
        return {"ok": True, "deleted_id": cid}

# ── API: Deals ────────────────────────────────────────────────────────────
@app.get("/api/deals")
async def list_deals(
    stage: str = "",
    limit: int = Query(100, ge=1, le=200),
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        q = """SELECT d.*, c.first_name||' '||c.last_name as contact_name
               FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE 1=1"""
        params = []
        if stage:
            q += " AND d.stage=?"
            params.append(stage)
        q += " ORDER BY d.created_at DESC LIMIT ?"
        params.append(limit)
        return {"deals": [dict(r) for r in db.execute(q, params).fetchall()]}

@app.post("/api/deals")
async def create_deal(
    d: DealCreate,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        contact = db.execute("SELECT id FROM contacts WHERE id=?", (d.contact_id,)).fetchone()
        if not contact:
            raise HTTPException(404, "Contact not found")
        cur = db.execute(
            "INSERT INTO deals (contact_id,title,value,stage,expected_close,notes) VALUES (?,?,?,?,?,?)",
            (d.contact_id, d.title, d.value, d.stage, d.expected_close, d.notes),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.put("/api/deals/{did}")
async def update_deal(
    did: int,
    d: DealUpdate,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        drow = db.execute("SELECT id FROM deals WHERE id=?", (did,)).fetchone()
        if not drow:
            raise HTTPException(404, "Deal not found")
        data = d.model_dump(exclude_unset=True)
        if not data:
            raise HTTPException(400, "No fields to update")
        sets = [f"{k}=?" for k in data]
        params = list(data.values()) + [did]
        db.execute(f"UPDATE deals SET {','.join(sets)},updated_at=datetime('now') WHERE id=?", params)
        return {"ok": True}

@app.delete("/api/deals/{did}")
async def delete_deal(
    did: int,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        drow = db.execute("SELECT id FROM deals WHERE id=?", (did,)).fetchone()
        if not drow:
            raise HTTPException(404, "Deal not found")
        db.execute("DELETE FROM deals WHERE id=?", (did,))
        return {"ok": True, "deleted_id": did}

# ── API: Activities ───────────────────────────────────────────────────────
@app.post("/api/activities")
async def create_activity(
    a: ActivityCreate,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        contact = db.execute("SELECT id FROM contacts WHERE id=?", (a.contact_id,)).fetchone()
        if not contact:
            raise HTTPException(404, "Contact not found")
        cur = db.execute(
            "INSERT INTO activities (contact_id,deal_id,type,subject,body,due_date) VALUES (?,?,?,?,?,?)",
            (a.contact_id, a.deal_id, a.type, a.subject, a.body, a.due_date),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.put("/api/activities/{aid}/done")
async def mark_activity_done(
    aid: int,
    auth: str = Depends(require_auth),
):
    with get_db() as db:
        row = db.execute("SELECT id FROM activities WHERE id=?", (aid,)).fetchone()
        if not row:
            raise HTTPException(404, "Activity not found")
        db.execute("UPDATE activities SET done=1 WHERE id=?", (aid,))
        return {"ok": True}

# ── API: Dashboard Stats ──────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(auth: str = Depends(require_auth)):
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
        by_status = {r[0]: r[1] for r in db.execute("SELECT status, COUNT(*) FROM contacts GROUP BY status").fetchall()}
        pipeline = {r[0]: r[1] for r in db.execute("SELECT stage, COUNT(*) FROM deals GROUP BY stage").fetchall()}
        pipeline_value = {r[0]: r[1] for r in db.execute("SELECT stage, SUM(value) FROM deals GROUP BY stage").fetchall()}
        won_value = db.execute("SELECT COALESCE(SUM(value),0) FROM deals WHERE stage='won'").fetchone()[0]
        open_deals = db.execute("SELECT COUNT(*) FROM deals WHERE stage NOT IN ('won','lost')").fetchone()[0]
        overdue = db.execute("SELECT COUNT(*) FROM activities WHERE done=0 AND due_date != '' AND due_date < date('now')").fetchone()[0]
        return {
            "total_contacts": total,
            "by_status": by_status,
            "pipeline": pipeline,
            "pipeline_value": pipeline_value,
            "won_value": won_value,
            "open_deals": open_deals,
            "overdue_tasks": overdue,
        }

# ── Frontend ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if not (cookie and verify_session_token(cookie) is not None):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "index.html", {})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)