"""Backend tests for /api/conversations CRUD and basic auth transition."""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://quantum-auth-5.preview.emergentagent.com"
API = f"{BASE_URL}/api"


@pytest.fixture(scope="module")
def user_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    # Try login as existing test user, else register
    r = s.post(f"{API}/auth/login", json={"identifier": "test1@example.com", "password": "Testpass123"})
    if r.status_code != 200:
        s.post(f"{API}/auth/register", json={"name": "Test User", "email": "test1@example.com", "password": "Testpass123"})
        r = s.post(f"{API}/auth/login", json={"identifier": "test1@example.com", "password": "Testpass123"})
    assert r.status_code == 200, r.text
    token = r.json()["session_token"]
    s.headers.update({"Authorization": f"Bearer {token}"})
    return s


@pytest.fixture(scope="module")
def guest_client():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{API}/auth/guest")
    assert r.status_code == 200, r.text
    s.headers.update({"Authorization": f"Bearer {r.json()['session_token']}"})
    return s


class TestAuthMe:
    def test_me_unauthenticated(self):
        r = requests.get(f"{API}/auth/me")
        assert r.status_code == 401

    def test_me_authenticated(self, user_client):
        r = user_client.get(f"{API}/auth/me")
        assert r.status_code == 200
        assert r.json()["user"]["email"] == "test1@example.com"


class TestConversationsCRUD:
    def test_requires_auth(self):
        r = requests.get(f"{API}/conversations")
        assert r.status_code == 401

    def test_create_get_update_delete(self, user_client):
        # Create
        r = user_client.post(f"{API}/conversations", json={"mode": "chat"})
        assert r.status_code == 200
        conv = r.json()["conversation"]
        conv_id = conv["conv_id"]
        assert conv["title"] == "New chat"
        assert conv["mode"] == "chat"
        assert conv["messages"] == []

        # List includes it
        r = user_client.get(f"{API}/conversations")
        assert r.status_code == 200
        assert any(c["conv_id"] == conv_id for c in r.json()["conversations"])

        # Update title + messages
        msgs = [
            {"id": "m1", "role": "user", "content": "TEST_hello", "created_at": "2026-01-01T00:00:00Z"},
            {"id": "m2", "role": "assistant", "status": "not_connected", "created_at": "2026-01-01T00:00:01Z"},
        ]
        r = user_client.patch(f"{API}/conversations/{conv_id}", json={"title": "TEST_conv_title", "messages": msgs})
        assert r.status_code == 200

        # Get verifies persistence
        r = user_client.get(f"{API}/conversations/{conv_id}")
        assert r.status_code == 200
        got = r.json()["conversation"]
        assert got["title"] == "TEST_conv_title"
        assert len(got["messages"]) == 2
        assert got["messages"][0]["content"] == "TEST_hello"

        # Delete
        r = user_client.delete(f"{API}/conversations/{conv_id}")
        assert r.status_code == 200

        r = user_client.get(f"{API}/conversations/{conv_id}")
        assert r.status_code == 404

    def test_delete_all(self, user_client):
        for _ in range(2):
            user_client.post(f"{API}/conversations", json={"mode": "chat"})
        r = user_client.delete(f"{API}/conversations")
        assert r.status_code == 200
        assert r.json()["deleted"] >= 2
        r = user_client.get(f"{API}/conversations")
        assert r.json()["conversations"] == []

    def test_user_isolation(self, user_client, guest_client):
        # user creates conv, guest cannot see it
        r = user_client.post(f"{API}/conversations", json={"mode": "chat"})
        cid = r.json()["conversation"]["conv_id"]
        r = guest_client.get(f"{API}/conversations/{cid}")
        assert r.status_code == 404
        user_client.delete(f"{API}/conversations/{cid}")

    def test_guest_can_create(self, guest_client):
        r = guest_client.post(f"{API}/conversations", json={"mode": "chat"})
        assert r.status_code == 200
        cid = r.json()["conversation"]["conv_id"]
        guest_client.delete(f"{API}/conversations/{cid}")
