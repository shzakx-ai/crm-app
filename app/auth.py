"""Authentication: HMAC session cookies, PBKDF2 passwords, login rate limiting,
FastAPI dependencies (require_auth / require_admin)."""
import hashlib
import hmac
import os
import secrets
import time
from typing import Dict, Optional

from fastapi import Depends, HTTPException, Request

from . import db
from .config import (
    API_TOKEN,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_WINDOW,
    SESSION_COOKIE,
    SESSION_SECRET,
    SESSION_TTL,
    TRUST_PROXY,
)

# ── Session tokens (stdlib HMAC-SHA256, no external deps) ────────────────
def _sign(msg: str, secret: str) -> str:
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def create_session_token(user_id: int = None) -> str:
    expires = int(time.time()) + SESSION_TTL
    uid = user_id if user_id is not None else 0
    payload = f"{expires}.{uid}"
    return f"{payload}.{_sign(payload, SESSION_SECRET)}"


def verify_session_token(token: str) -> Optional[int]:
    """Return user_id if valid, None otherwise."""
    try:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            return None
        payload, sig = parts
        if not hmac.compare_digest(_sign(payload, SESSION_SECRET), sig):
            return None
        exp_s, uid_s = payload.rsplit(".", 1)
        if int(exp_s) < time.time():
            return None
        return int(uid_s)
    except Exception:
        return None


# ── Passwords (PBKDF2-HMAC-SHA256) ───────────────────────────────────────
def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    iterations = 260_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt, expected = stored.split("$")
        if algo != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iter_s))
        return hmac.compare_digest(dk.hex(), expected)
    except Exception:
        return False


# ── User lookup helpers ──────────────────────────────────────────────────
def user_by_id(uid: int):
    with db.get_db() as conn:
        return conn.execute(
            "SELECT id, username, role FROM users WHERE id=?", (uid,)
        ).fetchone()


def user_by_username(username: str):
    with db.get_db() as conn:
        return conn.execute(
            "SELECT id, username, password_hash, role FROM users WHERE username=?", (username,)
        ).fetchone()


def api_bot_id() -> int:
    """Return the id of the api-bot system user (FK-safe owner for Bearer clients).

    Looked up lazily (DB may be empty until migrations run at app startup)."""
    with db.get_db() as conn:
        bot = conn.execute(
            "SELECT id FROM users WHERE username='api-bot'"
        ).fetchone()
        if bot:
            return bot["id"]
        admin = conn.execute(
            "SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1"
        ).fetchone()
        return admin["id"] if admin else 1


def get_api_bot_id() -> int:
    """Lazy accessor — safe to call after startup migrations."""
    return api_bot_id()


# ── Dependencies ─────────────────────────────────────────────────────────
async def require_auth(request: Request) -> dict:
    """Accept session cookie OR optional Bearer token. Returns user dict."""
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie:
        uid = verify_session_token(cookie)
        if uid is not None:
            user = user_by_id(uid)
            if user:
                return {"id": user["id"], "username": user["username"], "role": user["role"], "method": "session"}
    auth = request.headers.get("Authorization", "")
    if API_TOKEN and auth.startswith("Bearer "):
        supplied = auth[7:]
        if hmac.compare_digest(supplied, API_TOKEN):
            # Real FK-safe user id (api-bot) so created records have valid owner_id
            return {"id": get_api_bot_id(), "username": "api-client", "role": "admin", "method": "bearer"}
    raise HTTPException(status_code=401, detail="Authentication required")


def require_admin(user: dict = Depends(require_auth)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"


# ── Login rate limiting (per-IP + per-IP+username, in-memory) ────────────
_login_attempts: Dict[str, list] = {}


def login_ip(request: Request) -> str:
    """Direct client IP by default; X-Forwarded-For only when TRUST_PROXY=1."""
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_login_rate_limit(ip: str, username: str = ""):
    now = time.time()
    keys = [ip]
    if username:
        keys.append(f"{ip}:{username}")
    for key in keys:
        attempts = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW]
        _login_attempts[key] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            wait = int(LOGIN_WINDOW - (now - attempts[0]))
            raise HTTPException(status_code=429, detail=f"Too many attempts. Try again in {max(1, wait // 60)} min.")
    for key in keys:
        _login_attempts[key].append(now)
    return True