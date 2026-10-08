# Test Credentials — Quantum AI

## Admin account (seeded on startup)
- Email: admin@quantumai.app
- Password: Quantum@Admin2026
- Role: admin

## Test user (create via register or reuse if present)
- Name: Test User
- Email: test1@example.com
- Password: Testpass123
- Role: user

## Guest
- Created via POST /api/auth/guest (no credentials). is_guest=true, role=guest.

## Google login
- Emergent-managed Google OAuth. No app-managed password. Uses session_id -> /api/auth/google/session.

## Auth endpoints (all prefixed with /api)
- POST /api/auth/register {name, email, password}
- POST /api/auth/login {identifier, password}
- POST /api/auth/guest
- POST /api/auth/google/session {session_id}
- GET  /api/auth/me
- POST /api/auth/logout

## Session
- Opaque token in httpOnly cookie `session_token` (7 days). Also returned in JSON for testing.
