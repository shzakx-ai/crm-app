"""Row-level ownership scoping shared by routers.

Members only see/modify rows owned by their user id (contacts.owner_id);
admins have global visibility. Deals/activities inherit ownership through
the JOIN on contacts.
"""
from fastapi import HTTPException


def contact_scope(user: dict, alias: str = "") -> tuple[str, list]:
    """WHERE fragment (+ params) restricting contacts to the current user.
    alias: optional table alias, e.g. 'c' for JOINed queries."""
    prefix = f"{alias}." if alias else ""
    if user.get("role") == "admin":
        return "", []
    return f"{prefix}owner_id=?", [user["id"]]


def assert_owned_contact(db, user: dict, contact_id: int, alias: str = "") -> None:
    """Raise 404 unless the contact exists AND is visible to the user."""
    prefix = f"{alias}." if alias else ""
    q = f"SELECT id FROM contacts WHERE id=?"
    params: list = [contact_id]
    if user.get("role") != "admin":
        q += f" AND {prefix}owner_id=?"
        params.append(user["id"])
    row = db.execute(q, params).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Contact not found")