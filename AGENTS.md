# AGENTS.md

AI coding agent guidance for the Shelling AI vulnerability scanning platform. See [README.md](README.md) for overview, architecture diagrams, and quick-start commands.

## Project Shape

- **Backend:** FastAPI (`backend/app`) — async SQLAlchemy 2.0 + PostgreSQL, Motor + MongoDB, Redis, Celery tasks (`backend/tasks`).
- **Frontend:** React 18 + TypeScript + Vite (`frontend/src`), Tailwind CSS, React Query for server state, API layer in `frontend/src/lib/api.ts`.
- **Scanner runtime:** All scan tools execute via the Kali scanner microservice (`kali_scanner:8888`), never directly in the backend process.
- **Three-database architecture:** PostgreSQL for structured entities, MongoDB for raw scan data/logs, Redis for Celery broker + real-time scan logs.
- **Knowledge tools:** Uploaded scripts/templates/skills stored under `TOOLS_DIR` (`/app/data/tools`), shared across backend/celery_worker/kali_scanner via Docker volume.

## Key Files

| Area | Path | Purpose |
|------|------|---------|
| App entry | `backend/app/main.py` | FastAPI app, lifespan, CORS, router registration |
| Config | `backend/app/core/config.py` | `Settings` class (pydantic-settings), env vars |
| DB setup | `backend/app/core/database.py` | Async PG engine, MongoDB client, Redis client, `init_databases()` |
| Models | `backend/app/models/database.py` | All SQLAlchemy models (User, ScanTask, Vulnerability, SecurityTool, LLMConfig, AIPersona) |
| Schemas | `backend/app/schemas/` | Pydantic request/response models |
| Auth | `backend/app/api/auth.py` | JWT login/register, `get_current_user` dependency |
| RBAC | `backend/app/core/rbac.py` | Permission enum + role-permission mapping |
| Scan API | `backend/app/api/scans.py` | Scan CRUD, progress, logs, vulnerabilities |
| Scan tasks | `backend/tasks/scan_tasks.py` | Celery scan orchestration (long-running) |
| Scanners | `backend/scanners/` | Scanner abstractions via Kali HTTP API |
| LLM | `backend/llm/agent.py` | SecurityAgent (LangChain + ChatOpenAI) |
| Frontend API | `frontend/src/lib/api.ts` | Centralized axios instance + all API functions + TypeScript interfaces |
| Frontend app | `frontend/src/App.tsx` | Route definitions |
| Layout | `frontend/src/components/Layout.tsx` | Sidebar + header + `<Outlet/>` shell |
| Auth context | `frontend/src/contexts/AuthContext.tsx` | Auth state, login/logout, token management |

## Run & Validate

- **Full stack:** `docker compose up --build -d` from the repo root.
- **Dependencies only:** `docker compose up -d postgres mongodb redis` for local backend development.
- **Backend dev:** `cd backend && uvicorn app.main:app --reload` after installing `requirements.txt` and configuring `.env` if needed.
- **Worker dev:** `cd backend && celery -A tasks.celery_app worker --loglevel=info` in a separate terminal.
- **Frontend dev:** `cd frontend && npm install && npm run dev`.
- **Frontend build check:** `cd frontend && npm run build`.
- **Default admin:** `admin` / `admin123456` (change immediately in production).

## Backend Conventions

- Register API routers in `backend/app/main.py` with prefix from `settings.api_prefix` (`/api/v1` by default).
- Load configuration through `backend/app/core/config.py` (`pydantic-settings`); prefer environment variables over hard-coded values.
- Keep long-running scan orchestration in Celery tasks, especially `backend/tasks/scan_tasks.py`, instead of request handlers.
- Use existing scanner abstractions in `backend/scanners` and LLM abstractions in `backend/llm`; avoid duplicating scanner execution paths.
- Preserve async database/session patterns from `backend/app/core/database.py`; do not mix blocking DB work into async routes.
- **IDs:** All entity IDs are `str(uuid.uuid4())` (String(36)), never auto-increment integers.
- **Enums:** Use `SQLEnum` with Python enums for status/type fields; new enum values require PL/pgSQL migration in `init_databases()`.
- **Celery ↔ async bridge:** Celery tasks are synchronous; use the `run_async()` helper to bridge async code inside tasks. Celery uses its own `create_celery_session()` engine, not the FastAPI session factory.
- **API response pattern:** List endpoints return `{"total": int, "items": [...]}` with `skip`/`limit` pagination.
- **Access control:** Use `get_scan_task_with_access_check()` for scan detail endpoints; admins can access all scans, users only their own.
- **Logging:** Use `loguru` logger, not `print()` or stdlib `logging`.
- **Auth dependency chain:** `get_current_user(authorization: Header)` → validates JWT → returns `User`. `get_current_admin(user)` → checks `role == ADMIN`.

## Frontend Conventions

- Keep page-level UI in `frontend/src/pages` and shared layout/widgets in `frontend/src/components`.
- Use existing contexts for app-wide state (`AuthContext`, `ThemeContext`) rather than adding parallel global state.
- **State management:** Context for client state (auth, theme), React Query for server state. All queries use `staleTime: 30000` by default.
- **Real-time polling:** Running scans use conditional polling (2s interval for active, stop on complete). Logs use incremental fetch with `since_index` parameter (1s interval).
- **Mutations:** Use `useMutation` + `queryClient.invalidateQueries()` for write operations.
- **API layer:** All HTTP calls go through `lib/api.ts` axios instance. Auth endpoints in `AuthContext` use raw `fetch` (to avoid circular deps).
- **Styling:** Tailwind utility classes + `dark:` prefix for dark mode. Use `clsx` for conditional classes. Custom colors: `severity.critical/high/medium/low/info`.
- **Icons:** `lucide-react` with consistent `w-N h-N` sizing.
- **Routing:** `react-router-dom` v6 nested routes. `ProtectedRoute` guards auth; `requireAdmin` prop for admin-only pages.
- **UI language:** All user-facing text is in Chinese (中文).

## Scanner & LLM Architecture

- **Scanner execution:** All tools run through `KaliClient` (`backend/scanners/kali_client.py`) → HTTP POST to `kali_scanner:8888/execute`. The Kali container has 40+ pre-installed security tools.
- **Scanner registry:** `SCANNER_REGISTRY` maps `ScannerType` enum → scanner class. New scanners must be registered there.
- **Unified findings:** All scanners emit `ScanFinding` dataclass with `name`, `severity`, `category`, `description`, `location`, `evidence`.
- **LLM integration:** `SecurityAgent` (`backend/llm/agent.py`) uses LangChain `ChatOpenAI` (OpenAI-compatible API). Requires active `LLMConfig` in database.
- **AI personas:** Custom system prompts stored in `AIPersona` model; selectable per scan.

## Safety & Domain Rules

- This is a vulnerability scanning platform: do not add destructive exploitation behavior, DoS logic, or unauthorized scanning defaults.
- Follow existing agent/scanner safeguards: confirmed findings should include evidence; unconfirmed high/critical findings should be downgraded or clearly marked pending validation.
- Do not log or expose API keys, JWT secrets, LLM keys, uploaded secrets, or raw sensitive target data.
- The Kali scanner container is privileged by design; avoid expanding privileges or host mounts unless explicitly required.
- Credential testing and post-exploitation scanners are disabled by default; enable only with explicit user consent.

## Common Pitfalls

- **Kali URL:** `KALI_SCANNER_URL` defaults to `http://kali_scanner:8888` which only resolves inside Docker; override to `http://localhost:8888` for host-local runs.
- **TOOLS_DIR fallback:** Uploaded tool directories may fall back to `/tmp/shelling_tools` when `TOOLS_DIR` is not writable.
- **Frontend node_modules:** The frontend Docker service runs `npm install` on startup and mounts `/app/node_modules`; local and container dependency state can differ.
- **Service names:** Keep Docker service names (`postgres`, `mongodb`, `redis`, `kali_scanner`) aligned with connection strings in `docker-compose.yml`.
- **Celery event loop:** Never reuse the FastAPI async session factory inside Celery tasks; always use `create_celery_session()`.
- **DB migrations:** Schema changes require updating `init_databases()` in `database.py` with idempotent PL/pgSQL blocks (`DO $$ ... $$`). There is no Alembic.
- **Redirect slashes:** FastAPI has `redirect_slashes=False`; trailing slashes in routes will 404.
