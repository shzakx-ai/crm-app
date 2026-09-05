"""App configuration — everything from env, never hardcoded."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def get_db_path() -> str:
    """Read CRM_DB lazily so tests can point the app at another database."""
    return os.environ.get("CRM_DB", str(BASE_DIR / "crm.db"))


DB_PATH = get_db_path()
ADMIN_USER = os.environ.get("CRM_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("CRM_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
ADMIN_ROLE = "admin"
if not os.environ.get("CRM_ADMIN_PASSWORD"):
    print(f"⚠️  CRM_ADMIN_PASSWORD not set — generated admin password: {ADMIN_PASSWORD}")
    print(f"    Set CRM_ADMIN_PASSWORD in docker-compose/env for persistence.")
SESSION_SECRET = os.environ.get("CRM_SESSION_SECRET") or secrets.token_urlsafe(24)
API_TOKEN = os.environ.get("CRM_API_TOKEN") or None
if API_TOKEN:
    print("✅ CRM_API_TOKEN enabled for external API clients (Bearer).")

SESSION_TTL = 12 * 3600  # 12 hours
SESSION_COOKIE = "crm_session"
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW = 15 * 60  # 15 minutes

COOKIE_SECURE = os.environ.get("CRM_COOKIE_SECURE", "").lower() in ("1", "true")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "").lower() in ("1", "true")