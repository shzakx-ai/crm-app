"""v3 — ensure an api-bot system user exists for Bearer API clients.

Bearer tokens authenticate as a real FK-safe user so created records
always have a valid contacts.owner_id.

This migration is *conditional*: it only creates api-bot when an admin
already exists (legacy databases). On a fresh database there is no admin
yet — migration 003 is a no-op there, and create_app() completes seeding:
init_db() -> seed_admin() (admin, id 1) -> ensure_api_bot() (api-bot, id 2).
"""
import secrets


def migrate(conn):
    bot = conn.execute("SELECT id FROM users WHERE username='api-bot'").fetchone()
    if bot:
        return
    admin = conn.execute(
        "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
    ).fetchone()
    if admin:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            ("api-bot", secrets.token_urlsafe(32), "admin"),
        )