# Quantum AI — Auth Testing Playbook

Session model: opaque DB-backed session tokens (collection `user_sessions`), 7-day expiry, stored in httpOnly cookie `session_token` (also returned in JSON as `session_token` for header-based testing). Passwords hashed with bcrypt (`$2b$`).

## Admin credentials
- Email: admin@quantumai.app
- Password: Quantum@Admin2026
- Role: admin

## Endpoints (all under /api)
- POST /api/auth/register  {name, email, password}
- POST /api/auth/login     {identifier (email or display name), password}
- POST /api/auth/guest     (no body) -> temporary guest user + session
- POST /api/auth/google/session {session_id} -> Emergent Google OAuth exchange
- GET  /api/auth/me        (cookie or Bearer) -> current user
- POST /api/auth/logout    -> destroys session + clears cookie

## Step 1: MongoDB verification
```
mongosh
use test_database
db.users.findOne({role: "admin"})   // password_hash starts with $2b$
db.users.getIndexes()                // email unique(sparse), user_id unique
db.user_sessions.getIndexes()
```

## Step 2: API testing (cookie flow)
```
API=https://quantum-auth-5.preview.emergentagent.com
curl -c c.txt -X POST $API/api/auth/register -H "Content-Type: application/json" -d '{"name":"Test User","email":"test1@example.com","password":"Testpass123"}'
curl -b c.txt $API/api/auth/me
curl -c c2.txt -X POST $API/api/auth/login -H "Content-Type: application/json" -d '{"identifier":"admin@quantumai.app","password":"Quantum@Admin2026"}'
curl -b c2.txt $API/api/auth/me
curl -c g.txt -X POST $API/api/auth/guest
curl -b g.txt $API/api/auth/me   // is_guest true
```

## Cases to cover
- Register success / duplicate email (409) / invalid email (422) / short password (422)
- Login success / wrong password (401) / brute-force lockout after 5 (429)
- Guest login -> is_guest true, role guest
- /me without cookie -> 401
- Logout -> subsequent /me -> 401
- Google session with bad session_id -> 401
