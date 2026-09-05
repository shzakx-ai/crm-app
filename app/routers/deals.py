"""Deal CRUD — ownership flows through the contact join."""
from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import require_auth
from ..db import get_db
from ..models import DealCreate, DealUpdate
from ..services.ownership import assert_owned_contact, contact_scope

router = APIRouter(prefix="/api/deals", tags=["deals"])


@router.get("")
async def list_deals(
    stage: str = "",
    limit: int = Query(100, ge=1, le=200),
    auth: dict = Depends(require_auth),
):
    with get_db() as conn:
        q = """SELECT d.*, c.first_name||' '||c.last_name as contact_name
               FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE 1=1"""
        params: list = []
        scope, sp = contact_scope(auth, alias="c")
        if scope:
            q += f" AND {scope}"
            params.extend(sp)
        if stage:
            q += " AND d.stage=?"
            params.append(stage)
        q += " ORDER BY d.created_at DESC LIMIT ?"
        params.append(limit)
        return {"deals": [dict(r) for r in conn.execute(q, params).fetchall()]}


@router.post("")
async def create_deal(d: DealCreate, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        assert_owned_contact(conn, auth, d.contact_id)
        cur = conn.execute(
            "INSERT INTO deals (contact_id,title,value,stage,expected_close,notes) VALUES (?,?,?,?,?,?)",
            (d.contact_id, d.title, d.value, d.stage, d.expected_close, d.notes),
        )
        return {"id": cur.lastrowid, "ok": True}


@router.put("/{did}")
async def update_deal(did: int, d: DealUpdate, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        # Ownership of a deal is ownership of its contact.
        q = "SELECT contact_id FROM deals WHERE id=?"
        drow = conn.execute(q, (did,)).fetchone()
        if not drow:
            raise HTTPException(404, "Deal not found")
        assert_owned_contact(conn, auth, drow["contact_id"])
        data = d.model_dump(exclude_unset=True)
        if not data:
            raise HTTPException(400, "No fields to update")
        sets = [f"{k}=?" for k in data]
        conn.execute(
            f"UPDATE deals SET {','.join(sets)},updated_at=datetime('now') WHERE id=?",
            list(data.values()) + [did],
        )
        return {"ok": True}


@router.delete("/{did}")
async def delete_deal(did: int, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        q = "SELECT contact_id FROM deals WHERE id=?"
        drow = conn.execute(q, (did,)).fetchone()
        if not drow:
            raise HTTPException(404, "Deal not found")
        assert_owned_contact(conn, auth, drow["contact_id"])
        conn.execute("DELETE FROM deals WHERE id=?", (did,))
        return {"ok": True, "deleted_id": did}