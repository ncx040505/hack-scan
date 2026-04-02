# VulnScanner AI - Copilot Instructions

## Project Overview

LLM-integrated automated vulnerability scanning tool with FastAPI backend, React frontend, and Celery task queue.

## Tech Stack

- **Backend**: FastAPI (Python 3.11+), SQLAlchemy async, Pydantic v2
- **Frontend**: React 18, TypeScript, Vite, TailwindCSS, TanStack Query
- **Task Queue**: Celery + Redis
- **Databases**: PostgreSQL (structured data), MongoDB (raw scan data)
- **LLM**: LangChain with OpenAI-compatible API

## Build & Run Commands

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload                    # API server
celery -A tasks.celery_app worker --loglevel=info  # Worker

# Frontend
cd frontend
npm install
npm run dev      # Development
npm run build    # Production build
npm run lint     # ESLint

# Docker (all services)
cd docker && docker-compose up -d
```

## Architecture

```
backend/
├── app/
│   ├── api/          # FastAPI routers (scans.py, system.py)
│   ├── core/         # Config, database connections
│   ├── models/       # SQLAlchemy models
│   └── schemas/      # Pydantic schemas
├── llm/              # LangChain integration, VulnAnalyzer
├── scanners/         # Scanner implementations (base.py, nmap, nuclei)
└── tasks/            # Celery tasks

frontend/src/
├── components/       # Reusable UI components
├── pages/            # Route pages (Dashboard, NewScan, ScanDetail)
├── lib/              # API client, utilities
└── hooks/            # Custom React hooks
```

## Key Patterns

### Backend

- All database operations use async SQLAlchemy with `AsyncSession`
- API responses use Pydantic schemas from `app/schemas/`
- Scanners implement `BaseScanner` interface with async `scan()` generator
- LLM analysis uses structured output via `PydanticOutputParser`
- Long-running scans execute as Celery tasks, not in request handlers

### Frontend

- State management via TanStack Query (no Redux)
- API calls in `src/lib/api.ts` - add new endpoints there
- Tailwind for styling, dark theme by default
- Severity colors defined in `tailwind.config.js`

### Database

- `ScanTask`: Scan metadata, status, LLM summary
- `Vulnerability`: Individual findings with LLM analysis
- Raw scan output stored in MongoDB, referenced by `raw_data_ref`

## Adding a New Scanner

1. Create `backend/scanners/new_scanner.py` extending `BaseScanner`
2. Implement `is_available()` and `scan()` methods
3. Register in `backend/scanners/__init__.py`
4. Yield `ScanFinding` objects from `scan()`

## Security Considerations

- Never commit API keys; use `.env` file
- All scan targets must be validated before processing
- Rate limiting configured via `RATE_LIMIT_PER_TARGET`
- Sanitize data before sending to LLM (avoid leaking sensitive info)
