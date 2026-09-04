# CRM App

Lightweight Customer Relationship Management system built with FastAPI + SQLite.

## Features

- **Contact Management** — Add, edit, delete, search contacts
- **Deal Pipeline** — Track deals through Lead → Qualified → Proposal → Negotiation → Won/Lost
- **Dashboard** — Stats overview: contacts by status, pipeline value, overdue tasks
- **Activity Logging** — Notes, calls, emails, meetings, tasks
- **Dark UI** — Clean, responsive Bloomberg-style interface
- **🔐 Real Authentication** — Session-based login (HttpOnly cookie), no secrets in HTML
- **✅ Tested** — 22 automated tests covering auth, validation, CRUD, security

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env      # set CRM_ADMIN_PASSWORD + CRM_SESSION_SECRET
docker compose up --build
```

Open http://localhost:8000 → login with your admin credentials.

### Local

```bash
pip install -r requirements.txt
export CRM_ADMIN_USER=admin
export CRM_ADMIN_PASSWORD=your-password
export CRM_SESSION_SECRET=random-secret
python app.py
```

## Configuration (env vars)

| Variable | Default | Description |
|----------|---------|-------------|
| `CRM_ADMIN_USER` | `admin` | Login username |
| `CRM_ADMIN_PASSWORD` | *(generated)* | Login password. **Required in production** — without it, a random one is printed at startup |
| `CRM_SESSION_SECRET` | *(generated)* | HMAC key for session cookies. **Set it** for persistent sessions |
| `CRM_API_TOKEN` | *(disabled)* | Optional Bearer token for external API clients (not used by web UI) |
| `CRM_DB` | `crm.db` | SQLite database path |
| `CRM_COOKIE_SECURE` | `false` | Set `true` behind HTTPS (sets Secure flag on cookie) |
| `PORT` | `8000` | Uvicorn port |

## Security Model

- **No secrets in HTML/JS.** Login sets an HttpOnly, SameSite=Lax session cookie
- Session cookie is **HMAC-signed** (stdlib `hmac` + `hashlib`) with a 12h expiry
- The session secret never reaches the browser — it lives server-side only
- Optional Bearer token for external API clients (set `CRM_API_TOKEN`)
- Pydantic validation on all inputs (email format, status enums, string lengths)
- `limit`/`offset` bounded (1–200 / 0–10000)
- DELETE returns 404 for missing resources
- No external email-validator dependency — validation is light + dependency-free

## API Endpoints

All `/api/*` endpoints require either a valid session cookie or `Authorization: Bearer <CRM_API_TOKEN>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/login` | Login page |
| POST | `/login` | Authenticate (sets session cookie) |
| POST | `/logout` | Clear session |
| GET | `/api/me` | Check auth state |
| GET | `/api/contacts` | List contacts (search, filter, pagination) |
| POST | `/api/contacts` | Create contact |
| GET | `/api/contacts/{id}` | Get contact + deals + activities |
| PUT | `/api/contacts/{id}` | Update contact |
| DELETE | `/api/contacts/{id}` | Delete contact |
| GET | `/api/deals` | List deals (filter by stage) |
| POST | `/api/deals` | Create deal |
| PUT | `/api/deals/{id}` | Update deal (advance stage) |
| DELETE | `/api/deals/{id}` | Delete deal |
| POST | `/api/activities` | Log activity |
| PUT | `/api/activities/{id}/done` | Mark activity done |
| GET | `/api/stats` | Dashboard statistics |
| GET | `/docs` | OpenAPI docs (Swagger) |

## Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

22 tests covering: auth redirects, HttpOnly cookie, wrong-password rejection, Bearer auth, secret non-leakage, contact validation, email validator on create + update, 404 handling, limit bounds, deal creation, stats.

## CI

GitHub Actions runs `pytest` on every push/PR (`.github/workflows/ci.yml`).

## Tech Stack

- **Backend:** FastAPI + SQLite (WAL mode) + Pydantic v2
- **Auth:** HMAC-signed session cookies (stdlib only)
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Docker:** Python 3.12-slim + docker-compose

## License

MIT