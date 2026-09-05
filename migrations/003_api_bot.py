"""v3 — ensure an api-bot system user exists for Bearer API clients.

Bearer tokens authenticate as a real FK-safe user so created records
always have a valid contacts.owner_id. Runs AFTER the admin is seeded
(admin is the first user, id 1); api-bot is id 2 on fresh databases."""
import secrets


def migrate(conn):
    bot = conn.execute("SELECT id FROM users WHERE username='api-bot'").fetchone()
    if not bot:
        admin = conn.execute(
            "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
        ).fetchone()
        if admin:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                ("api-bot", secrets.token_urlsafe(32), "admin"),
            )