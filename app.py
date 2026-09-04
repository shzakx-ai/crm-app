#!/usr/bin/env python3
"""
CRM App v2 — Production-ready with Auth + Validation
FastAPI + SQLite + Pydantic. Docker-ready.
"""
import os
import sqlite3
from datetime import datetime
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any

# ── Config ────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("CRM_DB", "crm.db")
API_TOKEN = os.environ.get("CRM_API_TOKEN", "crm-dev-token-2026")

# ── Security ──────────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_token(token: str = Depends(oauth2_scheme)):
    if token != API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    return token

# ── App ───────────────────────────────────────────────────────────────────
app = FastAPI(title="CRM App", version="2.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── Pydantic Models ───────────────────────────────────────────────────────
class ContactCreate(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=50)
    last_name: str = Field(default="", max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: str = Field(default="lead", pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

class ContactUpdate(BaseModel):
    first_name: Optional[str] = Field(default=None, min_length=1, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    email: Optional[EmailStr] = None
    phone: Optional[str] = Field(default=None, max_length=30)
    company: Optional[str] = Field(default=None, max_length=100)
    position: Optional[str] = Field(default=None, max_length=100)
    status: Optional[str] = Field(default=None, pattern=r"^(lead|prospect|customer|inactive)$")
    source: Optional[str] = Field(default=None, max_length=100)
    notes: Optional[str] = Field(default=None, max_length=500)

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

# ── API: Auth ─────────────────────────────────────────────────────────────
@app.get("/token")
async def get_token():
    return {"access_token": API_TOKEN, "token_type": "bearer"}

# ── API: Contacts ─────────────────────────────────────────────────────────
@app.get("/api/contacts")
async def list_contacts(
    search: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
):
    with get_db() as db:
        db.execute("DELETE FROM contacts WHERE id=?", (cid,))
    return {"ok": True}

# ── API: Deals ────────────────────────────────────────────────────────────
@app.get("/api/deals")
async def list_deals(
    stage: str = "",
    limit: int = 100,
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
):
    with get_db() as db:
        db.execute("DELETE FROM deals WHERE id=?", (did,))
    return {"ok": True}

# ── API: Activities ───────────────────────────────────────────────────────
@app.post("/api/activities")
async def create_activity(
    a: ActivityCreate,
    token: str = Depends(get_current_token),
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
    token: str = Depends(get_current_token),
):
    with get_db() as db:
        db.execute("UPDATE activities SET done=1 WHERE id=?", (aid,))
    return {"ok": True}

# ── API: Dashboard Stats ──────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats(token: str = Depends(get_current_token)):
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
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)