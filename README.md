# CRM App

Lightweight Customer Relationship Management system built with FastAPI + SQLite.

## Features

- **Contact Management** — Add, edit, delete, search contacts
- **Deal Pipeline** — Track deals through Lead → Qualified → Proposal → Negotiation → Won/Lost
- **Dashboard** — Stats overview: contacts by status, pipeline value, overdue tasks
- **Activity Logging** — Notes, calls, emails, meetings, tasks
- **Dark UI** — Clean, responsive Bloomberg-style interface

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
```

Open http://localhost:8000

### Local

```bash
pip install -r requirements.txt
python app.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/contacts` | List contacts (search, filter) |
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

## Tech Stack

- **Backend:** FastAPI + SQLite (WAL mode)
- **Frontend:** Vanilla HTML/CSS/JS (no framework)
- **Docker:** Python 3.12-slim + docker-compose

## License

MIT
