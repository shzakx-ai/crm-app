# CRM App

Lightweight multi-user Customer Relationship Management system built with FastAPI + SQLite.

## Features

- **Multi-User with Roles** — `admin` and `member` roles; admins manage users
- **Contact Management** — Add, edit, delete, search contacts
- **Deal Pipeline** — Track deals through Lead → Qualified → Proposal → Negotiation → Won/Lost
- **Dashboard** — Stats overview: contacts by status, pipeline value, overdue tasks
- **Activity Logging** — Notes, calls, emails, meetings, tasks
- **Dark UI** — Clean, responsive Bloomberg-style interface
- **🔐 Real Authentication** — Session-based login (HttpOnly cookie), no secrets in HTML
- **🚦 Login Rate Limiting** — 5 attempts / 15 min per IP, 60s lockout
- **✅ Tested** — 27 automated tests covering auth, validation, CRUD, security, roles, rate limiting

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
- Session cookie is **HMAC-signed** (stdlib `hmac` + `hashlib`) with a 12h expiry, and carries the `user_id`
- The session secret never reaches the browser — it lives server-side only
- **Passwords hashed with PBKDF2-HMAC-SHA256** (260k iterations, per-user salt) — never stored in plaintext
- **Multi-user roles:** `admin` (full access + user management) vs `member` (CRUD only).
  `require_admin` guards the user-management APIs (403 for members)
- **Login rate limiting:** max 5 failed attempts per IP per 15 minutes → 429 with cooldown (mitigates brute-force)
- Optional Bearer token for external API clients (set `CRM_API_TOKEN`) — grants admin-level API access
- Pydantic validation on all inputs (email format, status enums, string lengths, username pattern, password ≥ 8)
- `limit`/`offset` bounded (1–200 / 0–10000)
- DELETE returns 404 for missing resources
- No external email-validator dependency — validation is light + dependency-free
- **Docker runs as non-root user** (`crm` uid 1000)

## Users & Roles

The first admin is seeded from `CRM_ADMIN_USER` / `CRM_ADMIN_PASSWORD` env vars.
Admins can then create additional users via the API:

```bash
# Create a member user (admin auth required)
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $CRM_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"sara","password":"strongpass123","role":"member"}'

# List users (admin only)
curl http://localhost:8000/api/users -H "Authorization: Bearer $CRM_API_TOKEN"

# Delete a user (admin only; cannot delete yourself)
curl -X DELETE http://localhost:8000/api/users/2 -H "Authorization: Bearer $CRM_API_TOKEN"
```

## API Endpoints

All `/api/*` endpoints require either a valid session cookie or `Authorization: Bearer <CRM_API_TOKEN>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/login` | Login page |
| POST | `/login` | Authenticate (sets session cookie) |
| POST | `/logout` | Clear session |
| GET | `/api/me` | Check auth state + role |
| GET | `/api/users` | *(admin)* List users |
| POST | `/api/users` | *(admin)* Create user |
| DELETE | `/api/users/{id}` | *(admin)* Delete user |
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

27 tests covering: auth redirects, HttpOnly cookie, wrong-password rejection, Bearer auth, secret non-leakage, contact validation, email validator on create + update, 404 handling, limit bounds, deal creation, stats, users/roles (admin vs member), duplicate username, login rate limiting.

## CI

GitHub Actions runs `pytest` on every push/PR (`.github/workflows/ci.yml`).

## Tech Stack

- **Backend:** FastAPI + SQLite (WAL mode) + Pydantic v2
- **Auth:** HMAC-signed session cookies (stdlib only)
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Docker:** Python 3.12-slim + docker-compose

## License

MIT