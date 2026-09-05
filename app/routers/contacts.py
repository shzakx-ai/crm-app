"""Contact CRUD with row-level ownership scoping."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import is_admin, require_auth
from ..db import get_db
from ..models import ContactCreate, ContactUpdate
from ..services.ownership import assert_owned_contact, contact_scope

router = APIRouter(prefix="/api/contacts", tags=["contacts"])


@router.get("")
async def list_contacts(
    search: str = "",
    status: str = "",
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0, le=10000),
    auth: dict = Depends(require_auth),
):
    with get_db() as conn:
        where = ["1=1"]
        params: list = []
        scope, sp = contact_scope(auth)
        if scope:
            where.append(scope)
            params.extend(sp)
        if search:
            where.append("(first_name||' '||last_name LIKE ? OR email LIKE ? OR company LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s, s])
        if status:
            where.append("status = ?")
            params.append(status)
        where_sql = " AND ".join(where)
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM contacts WHERE {where_sql} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()]
        total = conn.execute(
            f"SELECT COUNT(*) FROM contacts WHERE {where_sql}", params
        ).fetchone()[0]
        return {"contacts": rows, "total": total}


@router.post("")
async def create_contact(
    c: ContactCreate,
    auth: dict = Depends(require_auth),
):
    with get_db() as conn:
        cur = conn.execute(
            """INSERT INTO contacts (owner_id,first_name,last_name,email,phone,company,position,status,source,notes)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (auth["id"], c.first_name, c.last_name, c.email, c.phone, c.company, c.position, c.status, c.source, c.notes),
        )
        return {"id": cur.lastrowid, "ok": True}


@router.get("/{cid}")
async def get_contact(cid: int, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        q = "SELECT * FROM contacts WHERE id=?"
        params: list = [cid]
        if not is_admin(auth):
            q += " AND owner_id=?"
            params.append(auth["id"])
        row = conn.execute(q, params).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        deals = [dict(r) for r in conn.execute(
            "SELECT * FROM deals WHERE contact_id=? ORDER BY created_at DESC", (cid,)
        ).fetchall()]
        activities = [dict(r) for r in conn.execute(
            "SELECT * FROM activities WHERE contact_id=? ORDER BY created_at DESC LIMIT 50", (cid,)
        ).fetchall()]
        return {"contact": dict(row), "deals": deals, "activities": activities}


@router.put("/{cid}")
async def update_contact(cid: int, c: ContactUpdate, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        q = "SELECT id FROM contacts WHERE id=?"
        params: list = [cid]
        if not is_admin(auth):
            q += " AND owner_id=?"
            params.append(auth["id"])
        row = conn.execute(q, params).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        data = c.model_dump(exclude_unset=True)
        if not data:
            raise HTTPException(400, "No fields to update")
        sets = [f"{k}=?" for k in data]
        conn.execute(
            f"UPDATE contacts SET {','.join(sets)},updated_at=datetime('now') WHERE id=?",
            list(data.values()) + [cid],
        )
        updated = conn.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
        return {"ok": True, "contact": dict(updated)}


@router.delete("/{cid}")
async def delete_contact(cid: int, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        q = "SELECT id FROM contacts WHERE id=?"
        params: list = [cid]
        if not is_admin(auth):
            q += " AND owner_id=?"
            params.append(auth["id"])
        row = conn.execute(q, params).fetchone()
        if not row:
            raise HTTPException(404, "Contact not found")
        conn.execute("DELETE FROM contacts WHERE id=?", (cid,))
        return {"ok": True, "deleted_id": cid}