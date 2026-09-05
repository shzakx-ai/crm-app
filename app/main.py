"""FastAPI application factory — wires config, migrations, seeding, routers."""
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import auth as auth_mod
from .config import ADMIN_PASSWORD, ADMIN_ROLE, ADMIN_USER
from .db import get_db, init_db
from .routers import activities, auth, contacts, deals, frontend, stats, users


def seed_admin():
    """Insert the env-configured admin if not present."""
    with get_db() as conn:
        exists = conn.execute("SELECT id FROM users WHERE username=?", (ADMIN_USER,)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (ADMIN_USER, auth_mod.hash_password(ADMIN_PASSWORD), ADMIN_ROLE),
            )
            print(f"✅ Seeded admin user: {ADMIN_USER} (role=admin)")


def ensure_api_bot():
    """Guarantee api-bot exists after admin seeding (FK-safe owner for Bearer)."""
    import secrets

    with get_db() as conn:
        bot = conn.execute("SELECT id FROM users WHERE username='api-bot'").fetchone()
        if not bot:
            admin = conn.execute(
                "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
            ).fetchone()
            if not admin:
                return
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                ("api-bot", auth_mod.hash_password(secrets.token_urlsafe(24)), "admin"),
            )
            print("🧬 Seeded api-bot user for Bearer clients")


def create_app() -> FastAPI:
    init_db()          # runs versioned migrations
    seed_admin()
    ensure_api_bot()

    app = FastAPI(title="CRM App", version="4.0.0", docs_url="/docs")
    app.mount("/static", StaticFiles(directory="static"), name="static")

    app.include_router(auth.router)
    app.include_router(frontend.router)
    app.include_router(users.router)
    app.include_router(contacts.router)
    app.include_router(deals.router)
    app.include_router(activities.router)
    app.include_router(stats.router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)