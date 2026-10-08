# Quantum AI — Product Requirements & Progress

## Original Problem Statement
Build STEP 1 of Quantum AI: a complete, production-ready authentication system ONLY. No AI chat engine, tools, image generation, file analysis, or workspace yet. Must include branded login, sign up, logout, session persistence, protected sessions, guest mode, loading/error states, and mobile+desktop responsiveness. Design: futuristic, clean, premium, minimal dark aesthetic. Consistent "Quantum AI" branding.

## User Choices
- Auth: Both JWT (email/password) AND Emergent-managed Google login
- Theme: Dark futuristic (deep space/black + neon cyan/blue/purple accents)
- Guest: temporary guest record in the database, clearly identified, no account-only access
- Extras: "Remember me" + password strength meter
- Logo: user-provided 3D swirling vortex orb (`/frontend/public/quantum-logo.png`)

## Architecture
- Backend: FastAPI (`/app/backend/server.py`), MongoDB (motor), bcrypt password hashing, opaque DB-backed session tokens (collection `user_sessions`, 7-day expiry) stored in httpOnly `session_token` cookie (secure, samesite=none). Brute-force lockout (5 fails → 15 min, `login_attempts`).
- Collections: `users` (user_id, email[partial-unique], name, password_hash, picture, role, is_guest, auth_provider, created_at), `user_sessions`, `login_attempts`.
- Auth endpoints (all `/api/auth/*`): register, login (identifier=email or display name), guest, google/session, me, logout.
- Frontend: React + react-router v7. `AuthContext` (null=checking / false=unauth / object=auth), `ProtectedRoute`, `AuthCallback` (Google OAuth hash exchange), `AuthPage` (login/signup toggle), `Dashboard` (session verification landing). Design in `/app/design_guidelines.json`.

## User Personas
- New user (creates account), returning user (login), admin (seeded), guest (temporary exploration).

## Core Requirements (static)
- Secure auth, no secrets in frontend, protected routes, session persistence, guest isolation, responsive UI, consistent branding.

## Implemented (2026-09-26)
- ✅ Full JWT-style email/password auth (register, login, logout, /me) with bcrypt + DB sessions
- ✅ Emergent Google login (redirect + backend session-data exchange + AuthCallback)
- ✅ Guest mode (temporary DB record, guest badge, locked-feature notice) — fixed null-email partial index bug
- ✅ Session persistence across refresh via httpOnly cookie
- ✅ Protected routes redirect unauthenticated users to /auth
- ✅ Password strength meter, remember-me, show/hide password, validation, error alerts, loading states
- ✅ Dark futuristic responsive UI (desktop + mobile), Quantum AI branding + user logo
- ✅ Admin seeded on startup; test_credentials.md + auth_testing.md written
- ✅ Tested: testing agent 9/10 backend + 13/14 frontend; guest bug fixed & re-verified

## Implemented (2026-09-26) — Step 2: Application Shell & Multi-Model Interface
- ✅ App shell: collapsible sidebar (desktop) + drawer (mobile), topbar with model selector + profile menu
- ✅ Conversation sidebar: New Chat, search, date grouping (Today/Yesterday/Previous 7 days/Older), rename, delete, per-user persistence via /api/conversations CRUD (backend: create/list/get/patch/delete/delete-all, owner-scoped)
- ✅ Chat workspace: welcome screen ("What can Quantum AI help you with?") + 6 task cards that prepare model/mode, user messages with timestamps + copy, honest "model isn't connected yet" AI containers (NO fake responses), disabled regenerate until providers connect
- ✅ Model selector: ChatGPT, Gemini, Claude, Perplexity, Image Generation — all marked "Not connected"; Quantum Mode entry disabled "Coming soon" (UI foundation for multi-model orchestration)
- ✅ Composer: multiline auto-resize, Enter to send / Shift+Enter newline, attach button (roadmap toast), image-generation mode toggle, loading + disabled states
- ✅ Provider abstraction: /app/frontend/src/providers/aiProviders.js — registry + standardized queryProvider() contract (throws PROVIDER_NOT_CONNECTED; Step 3 plugs real APIs in here, no keys in frontend)
- ✅ Settings page /settings: Appearance (dark default), Account (real user info + logout), Default model (persisted to localStorage), AI prefs/Notifications/Privacy (honest placeholders), Data controls (real delete-all conversations)
- ✅ Guest experience: guest badge in profile menu, amber temporary notice in sidebar, full basic interface access
- ✅ User profile menu: display name, email/guest status, settings, logout
- ✅ Tested: testing agent 100% backend (7/7 conversation tests) + 100% frontend (all flows incl. persistence after reload, mobile 390px + desktop 1920px). Minor toast-overlap on mobile fixed (bottom-center toasts on small screens).

## Implemented (2026-09-26) — Step 3: Real AI Providers, Image Generation & Attachments
- ✅ Connected ChatGPT (openai gpt-5.4), Gemini (gemini-3.1-pro-preview), Claude (anthropic claude-sonnet-4-6) via Emergent LLM key (emergentintegrations), SSE token streaming (`POST /api/chat/stream`), multi-turn context via system prompt, responses persisted per conversation
- ✅ Image generation via Gemini Nano Banana (gemini-3.1-flash-image-preview) — `POST /api/chat/image`, images stored in Emergent Object Storage, served via `GET /api/files/{path}`
- ✅ Attachments: `POST /api/upload` (PNG/JPG/WebP/GIF + PDF/TXT, 15MB cap, ext validated) to object storage; images passed to vision models as ImageContent, txt/csv/json content injected into prompt, pdf referenced
- ✅ Frontend: real streaming into chat (typing cursor), image rendering, regenerate re-runs last prompt, copy works, attachment chips in composer + user messages, model selector shows "Connected", Quantum Mode still "Coming soon"
- ✅ Perplexity REMOVED per user request
- ✅ Backend smoke-tested: streaming (3 providers), image gen + serve, upload + validation + auth guards all pass

## Backlog (future steps)
- P1: Quantum Mode orchestration (multi-model synthesis), streaming for image progress, PDF text extraction
- P2: Password reset email (Resend), guest→account upgrade, settings: notifications/privacy/AI prefs, conversation search backend, user-provided API keys

## Notes
- AI/model/storage/search integrations were requested by the user but are intentionally deferred to later steps. Step 1 is auth-only and stable.
