"""Dashboard stats — all counts scoped to the current user."""
from fastapi import APIRouter, Depends

from ..auth import is_admin, require_auth
from ..db import get_db

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
async def get_stats(auth: dict = Depends(require_auth)):
    with get_db() as conn:
        admin = is_admin(auth)
        scope_c = "" if admin else " AND owner_id=?"
        scope_d = "" if admin else " AND c.owner_id=?"
        sp = [auth["id"]] if not admin else []

        total = conn.execute(
            "SELECT COUNT(*) FROM contacts WHERE 1=1" + scope_c, sp
        ).fetchone()[0]
        by_status = {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM contacts WHERE 1=1" + scope_c + " GROUP BY status", sp
        ).fetchall()}
        pipeline = {r[0]: r[1] for r in conn.execute(
            "SELECT d.stage, COUNT(*) FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE 1=1" + scope_d + " GROUP BY d.stage",
            sp,
        ).fetchall()}
        pipeline_value = {r[0]: r[1] for r in conn.execute(
            "SELECT d.stage, SUM(d.value) FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE 1=1" + scope_d + " GROUP BY d.stage",
            sp,
        ).fetchall()}
        won_value = conn.execute(
            "SELECT COALESCE(SUM(d.value),0) FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE d.stage='won'" + scope_d,
            sp,
        ).fetchone()[0]
        open_deals = conn.execute(
            "SELECT COUNT(*) FROM deals d JOIN contacts c ON d.contact_id=c.id WHERE d.stage NOT IN ('won','lost')" + scope_d,
            sp,
        ).fetchone()[0]
        overdue = conn.execute(
            "SELECT COUNT(*) FROM activities a JOIN contacts c ON a.contact_id=c.id WHERE a.done=0 AND a.due_date != '' AND a.due_date < date('now')" + scope_d,
            sp,
        ).fetchone()[0]
        return {
            "total_contacts": total,
            "by_status": by_status,
            "pipeline": pipeline,
            "pipeline_value": pipeline_value,
            "won_value": won_value,
            "open_deals": open_deals,
            "overdue_tasks": overdue,
        }