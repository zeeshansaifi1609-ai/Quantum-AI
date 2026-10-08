"""Backend regression tests for Quantum AI auth endpoints."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://quantum-auth-5.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@quantumai.app"
ADMIN_PASSWORD = "Quantum@Admin2026"


@pytest.fixture
def s():
    return requests.Session()


# --- Register ---
class TestRegister:
    def test_register_success(self, s):
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        r = s.post(f"{API}/auth/register", json={"name": "TestUser", "email": email, "password": "Testpass123"})
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["user"]["email"] == email
        assert data["user"]["is_guest"] is False
        assert data["user"]["role"] == "user"
        assert "session_token" in data
        # verify /me
        me = s.get(f"{API}/auth/me")
        assert me.status_code == 200
        assert me.json()["user"]["email"] == email

    def test_register_duplicate(self, s):
        email = f"dup_{uuid.uuid4().hex[:8]}@example.com"
        s.post(f"{API}/auth/register", json={"name": "DupUser", "email": email, "password": "Testpass123"})
        r = requests.post(f"{API}/auth/register", json={"name": "DupUser2", "email": email, "password": "Testpass123"})
        assert r.status_code == 409
        assert "exists" in r.json()["detail"].lower()

    def test_register_short_password(self, s):
        r = s.post(f"{API}/auth/register", json={"name": "Ab", "email": f"a_{uuid.uuid4().hex[:6]}@x.com", "password": "short"})
        assert r.status_code == 422

    def test_register_invalid_email(self, s):
        r = s.post(f"{API}/auth/register", json={"name": "Abcd", "email": "not-an-email", "password": "Testpass123"})
        assert r.status_code == 422

    def test_register_short_name(self, s):
        r = s.post(f"{API}/auth/register", json={"name": "A", "email": f"n_{uuid.uuid4().hex[:6]}@x.com", "password": "Testpass123"})
        assert r.status_code == 422


# --- Login ---
class TestLogin:
    def test_admin_login(self):
        s = requests.Session()
        r = s.post(f"{API}/auth/login", json={"identifier": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        assert r.json()["user"]["role"] == "admin"
        me = s.get(f"{API}/auth/me")
        assert me.status_code == 200
        assert me.json()["user"]["role"] == "admin"

    def test_wrong_password(self):
        r = requests.post(f"{API}/auth/login", json={"identifier": ADMIN_EMAIL, "password": "WrongPass!!"})
        assert r.status_code == 401
        assert "invalid" in r.json()["detail"].lower()

    def test_unauth_me(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code == 401


# --- Guest ---
class TestGuest:
    def test_guest_creates_session(self):
        s = requests.Session()
        r = s.post(f"{API}/auth/guest")
        assert r.status_code == 200
        u = r.json()["user"]
        assert u["is_guest"] is True
        assert u["role"] == "guest"
        assert u["email"] is None
        assert u["name"].startswith("Guest-")


# --- Logout ---
class TestLogout:
    def test_logout_flow(self):
        s = requests.Session()
        email = f"lo_{uuid.uuid4().hex[:8]}@example.com"
        s.post(f"{API}/auth/register", json={"name": "LoUser", "email": email, "password": "Testpass123"})
        assert s.get(f"{API}/auth/me").status_code == 200
        r = s.post(f"{API}/auth/logout")
        assert r.status_code == 200
        # After logout, session invalid
        s2 = requests.Session()
        assert s2.get(f"{API}/auth/me").status_code == 401
