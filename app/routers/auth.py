"""Auth routes: /login page, login/logout, /api/me."""
import hmac
import os

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from .. import auth as auth_mod
from ..config import API_TOKEN, COOKIE_SECURE, SESSION_COOKIE, SESSION_TTL

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie and auth_mod.verify_session_token(cookie) is not None:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html", {})


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    user = auth_mod.user_by_username(username)
    if not user or not auth_mod.verify_password(password, user["password_hash"]):
        ip = auth_mod.login_ip(request)
        auth_mod.check_login_rate_limit(ip, username)
        raise HTTPException(status_code=401, detail="Invalid credentials or account locked")
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        SESSION_COOKIE,
        auth_mod.create_session_token(user_id=user["id"]),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
        secure=COOKIE_SECURE,
        path="/",
    )
    return resp


@router.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/api/me")
async def me(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if cookie:
        uid = auth_mod.verify_session_token(cookie)
        if uid is not None:
            user = auth_mod.user_by_id(uid)
            if user:
                return {"authenticated": True, "user": user["username"], "role": user["role"], "method": "session"}
    auth = request.headers.get("Authorization", "")
    if API_TOKEN and auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], API_TOKEN):
        return {"authenticated": True, "user": "api-client", "role": "admin", "method": "bearer"}
    return JSONResponse({"authenticated": False}, status_code=401)