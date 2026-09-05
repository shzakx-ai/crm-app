"""Admin-only user management: list, create, delete (with data-loss guard)."""
from fastapi import APIRouter, Depends, HTTPException

from .. import db
from ..auth import get_api_bot_id, hash_password, require_admin, require_auth
from ..models import UserCreate
from ..db import get_db

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", dependencies=[Depends(require_admin)])
async def list_users():
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id"
        ).fetchall()]
        return {"users": rows}


@router.post("", dependencies=[Depends(require_admin)])
async def create_user(u: UserCreate):
    with get_db() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username=?", (u.username,)).fetchone()
        if exists:
            raise HTTPException(409, "Username already exists")
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (u.username, hash_password(u.password), u.role),
        )
        return {"id": cur.lastrowid, "ok": True}


@router.delete("/{uid}", dependencies=[Depends(require_admin)])
async def delete_user(uid: int, auth: dict = Depends(require_auth)):
    if uid == auth["id"]:
        raise HTTPException(400, "Cannot delete your own account")
    if uid == get_api_bot_id():
        raise HTTPException(400, "Cannot delete the system api-bot user")
    with get_db() as conn:
        row = conn.execute("SELECT id, username FROM users WHERE id=?", (uid,)).fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        # Refuse to delete a user with owned data — would cascade-delete their CRM records.
        contact_count = conn.execute(
            "SELECT COUNT(*) FROM contacts WHERE owner_id=?", (uid,)
        ).fetchone()[0]
        if contact_count > 0:
            raise HTTPException(
                409,
                f"User '{row['username']}' owns {contact_count} contact(s); "
                "reassign or delete their records first to prevent data loss",
            )
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        return {"ok": True, "deleted_id": uid}