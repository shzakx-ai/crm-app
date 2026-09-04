#!/usr/bin/env python3
"""
CRM App — Lightweight Customer Relationship Management
Built with FastAPI + SQLite. Docker-ready.
"""
import os
import sqlite3
import json
from datetime import datetime, date
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ── Database ──────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("CRM_DB", "crm.db")

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

# ── App ───────────────────────────────────────────────────────────────────
app = FastAPI(title="CRM App", version="1.0.0")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ── API: Contacts ─────────────────────────────────────────────────────────
@app.get("/api/contacts")
def list_contacts(search: str = "", status: str = "", limit: int = 100, offset: int = 0):
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
def create_contact(
    first_name: str = Form(...),
    last_name: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
    company: str = Form(""),
    position: str = Form(""),
    status: str = Form("lead"),
    source: str = Form(""),
    notes: str = Form(""),
):
    with get_db() as db:
        cur = db.execute(
            """INSERT INTO contacts (first_name,last_name,email,phone,company,position,status,source,notes)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (first_name, last_name, email, phone, company, position, status, source, notes),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.get("/api/contacts/{cid}")
def get_contact(cid: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        deals = [dict(r) for r in db.execute("SELECT * FROM deals WHERE contact_id=? ORDER BY created_at DESC", (cid,)).fetchall()]
        activities = [dict(r) for r in db.execute("SELECT * FROM activities WHERE contact_id=? ORDER BY created_at DESC LIMIT 50", (cid,)).fetchall()]
        return {"contact": dict(row), "deals": deals, "activities": activities}

@app.put("/api/contacts/{cid}")
def update_contact(cid: int, request: Request):
    import asyncio
    async def _update():
        data = await request.json()
        fields = ["first_name","last_name","email","phone","company","position","status","source","notes"]
        sets = []
        params = []
        for f in fields:
            if f in data:
                sets.append(f"{f}=?")
                params.append(data[f])
        if not sets:
            raise HTTPException(400, "No fields to update")
        sets.append("updated_at=datetime('now')")
        params.append(cid)
        with get_db() as db:
            db.execute(f"UPDATE contacts SET {','.join(sets)} WHERE id=?", params)
        return {"ok": True}
    return asyncio.get_event_loop().run_until_complete(_update())

@app.delete("/api/contacts/{cid}")
def delete_contact(cid: int):
    with get_db() as db:
        db.execute("DELETE FROM contacts WHERE id=?", (cid,))
    return {"ok": True}

# ── API: Deals ────────────────────────────────────────────────────────────
@app.get("/api/deals")
def list_deals(stage: str = "", limit: int = 100):
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
def create_deal(
    contact_id: int = Form(...),
    title: str = Form(...),
    value: float = Form(0),
    stage: str = Form("lead"),
    expected_close: str = Form(""),
    notes: str = Form(""),
):
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO deals (contact_id,title,value,stage,expected_close,notes) VALUES (?,?,?,?,?,?)",
            (contact_id, title, value, stage, expected_close, notes),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.put("/api/deals/{did}")
def update_deal(did: int, request: Request):
    import asyncio
    async def _update():
        data = await request.json()
        fields = ["title","value","stage","expected_close","notes"]
        sets = []
        params = []
        for f in fields:
            if f in data:
                sets.append(f"{f}=?")
                params.append(data[f])
        if not sets:
            raise HTTPException(400, "No fields")
        sets.append("updated_at=datetime('now')")
        params.append(did)
        with get_db() as db:
            db.execute(f"UPDATE deals SET {','.join(sets)} WHERE id=?", params)
        return {"ok": True}
    return asyncio.get_event_loop().run_until_complete(_update())

@app.delete("/api/deals/{did}")
def delete_deal(did: int):
    with get_db() as db:
        db.execute("DELETE FROM deals WHERE id=?", (did,))
    return {"ok": True}

# ── API: Activities ───────────────────────────────────────────────────────
@app.post("/api/activities")
def create_activity(
    contact_id: int = Form(...),
    deal_id: int = Form(0),
    type: str = Form("note"),
    subject: str = Form(""),
    body: str = Form(""),
    due_date: str = Form(""),
):
    with get_db() as db:
        cur = db.execute(
            "INSERT INTO activities (contact_id,deal_id,type,subject,body,due_date) VALUES (?,?,?,?,?,?)",
            (contact_id, deal_id or None, type, subject, body, due_date),
        )
        return {"id": cur.lastrowid, "ok": True}

@app.put("/api/activities/{aid}/done")
def mark_activity_done(aid: int):
    with get_db() as db:
        db.execute("UPDATE activities SET done=1 WHERE id=?", (aid,))
    return {"ok": True}

# ── API: Dashboard Stats ──────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
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
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
