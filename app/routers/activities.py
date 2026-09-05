"""Activity routes (create + mark done) — ownership via contact join."""
from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_auth
from ..db import get_db
from ..models import ActivityCreate
from ..services.ownership import assert_owned_contact

router = APIRouter(prefix="/api/activities", tags=["activities"])


@router.post("")
async def create_activity(a: ActivityCreate, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        assert_owned_contact(conn, auth, a.contact_id)
        cur = conn.execute(
            "INSERT INTO activities (contact_id,deal_id,type,subject,body,due_date) VALUES (?,?,?,?,?,?)",
            (a.contact_id, a.deal_id, a.type, a.subject, a.body, a.due_date),
        )
        return {"id": cur.lastrowid, "ok": True}


@router.put("/{aid}/done")
async def mark_activity_done(aid: int, auth: dict = Depends(require_auth)):
    with get_db() as conn:
        q = "SELECT contact_id FROM activities WHERE id=?"
        row = conn.execute(q, (aid,)).fetchone()
        if not row:
            raise HTTPException(404, "Activity not found")
        assert_owned_contact(conn, auth, row["contact_id"])
        conn.execute("UPDATE activities SET done=1 WHERE id=?", (aid,))
        return {"ok": True}