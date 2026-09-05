"""Frontend routes: index page (session-gated)."""
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import auth as auth_mod
from ..config import SESSION_COOKIE

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if not (cookie and auth_mod.verify_session_token(cookie) is not None):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse(request, "index.html", {})