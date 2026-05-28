# AGENTS.md

Guidance for AI coding agents working in this repository. Keep changes focused, safe, and consistent with the existing FastAPI + React architecture. See [README.md](README.md) for product overview, diagrams, and quick-start commands.

## Project Shape

- **Backend:** FastAPI app under `backend/app`, async SQLAlchemy/PostgreSQL, Motor/MongoDB, Redis, and Celery tasks under `backend/tasks`.
- **Frontend:** React + TypeScript + Vite app under `frontend/src`, with Tailwind utility classes and API access centralized in `frontend/src/lib/api.ts`.
- **Scanner runtime:** Scanning tools execute through the Kali scanner service/container, not directly in the backend process.
- **Persistence:** PostgreSQL stores structured entities, MongoDB stores raw scan data/log-oriented payloads, Redis backs Celery.
- **Knowledge tools:** Uploaded tools and skills are managed by the backend tools API and stored under `TOOLS_DIR` (`/app/data/tools` in containers).

## Run & Validate

- **Full stack:** `docker compose up --build -d` from the repo root.
- **Dependencies only:** `docker compose up -d postgres mongodb redis` for local backend development.
- **Backend dev:** `cd backend && uvicorn app.main:app --reload` after installing `requirements.txt` and configuring `.env` if needed.
- **Worker dev:** `cd backend && celery -A tasks.celery_app worker --loglevel=info` in a separate terminal.
- **Frontend dev:** `cd frontend && npm install && npm run dev`.
- **Frontend checks:** `cd frontend && npm run build`; `npm run lint` exists but this repo does not currently include an ESLint config in the visible tree, so verify before relying on it.

## Backend Conventions

- Register API routers in `backend/app/main.py` with prefix from `settings.api_prefix` (`/api/v1` by default).
- Load configuration through `backend/app/core/config.py` (`pydantic-settings`); prefer environment variables over hard-coded values.
- Keep long-running scan orchestration in Celery tasks, especially `backend/tasks/scan_tasks.py`, instead of request handlers.
- Use existing scanner abstractions in `backend/scanners` and LLM abstractions in `backend/llm`; avoid duplicating scanner execution paths.
- Preserve async database/session patterns from `backend/app/core/database.py`; do not mix blocking DB work into async routes.

## Frontend Conventions

- Keep page-level UI in `frontend/src/pages` and shared layout/widgets in `frontend/src/components`.
- Use existing contexts for app-wide state (`AuthContext`, `ThemeContext`) rather than adding parallel global state.
- Keep API URLs relative to Vite proxy/container config where possible; Docker sets `VITE_API_URL=/api/v1`.
- Match the current Tailwind-first styling approach and dark-mode class patterns.

## Safety & Domain Rules

- This is a vulnerability scanning platform: do not add destructive exploitation behavior, DoS logic, or unauthorized scanning defaults.
- Follow existing agent/scanner safeguards: confirmed findings should include evidence; unconfirmed high/critical findings should be downgraded or clearly marked pending validation.
- Do not log or expose API keys, JWT secrets, LLM keys, uploaded secrets, or raw sensitive target data.
- The Kali scanner container is privileged by design; avoid expanding privileges or host mounts unless explicitly required.

## Common Pitfalls

- Local backend defaults point `KALI_SCANNER_URL` at `http://kali_scanner:8888`, which only resolves inside Docker; override it for host-local runs.
- Uploaded tool directories may fall back to `/tmp/shelling_tools` when `TOOLS_DIR` is not writable.
- The frontend Docker service runs `npm install` on startup and mounts `/app/node_modules`; local and container dependency state can differ.
- Keep Docker service names (`postgres`, `mongodb`, `redis`, `kali_scanner`) aligned with connection strings in `docker-compose.yml`.
