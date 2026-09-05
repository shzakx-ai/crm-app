"""Row-level ownership scoping shared by routers.

Members only see/modify rows owned by their user id (contacts.owner_id);
admins have global visibility. Deals/activities inherit ownership through
the JOIN on contacts.
"""
from fastapi import HTTPException


def contact_scope(user: dict, alias: str = "") -> tuple[str, list]:
    """WHERE fragment (+ params) restricting contacts to the current user.
    alias: optional table alias (e.g. 'c') for JOINed queries.
    Returns ("", []) for admins (no restriction)."""
    prefix = f"{alias}." if alias else ""
    if user.get("role") == "admin":
        return "", []
    return f"{prefix}owner_id=?", [user["id"]]


def assert_owned_contact(db, user: dict, contact_id: int, alias: str = "") -> None:
    """Raise 404 unless the contact exists AND is visible to the user.

    alias is a table alias used in an *outer* FROM/JOIN — the query is built
    to reference the contacts table by that alias if provided, so aliased
    queries (e.g. `FROM contacts c`) work the same as unaliased ones.
    """
    table = f"contacts {alias}" if alias else "contacts"
    q = f"SELECT id FROM {table} WHERE id=?"
    params: list = [contact_id]
    scope, sp = contact_scope(user, alias)
    if scope:
        q += f" AND {scope}"
        params.extend(sp)
    row = db.execute(q, params).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Contact not found")