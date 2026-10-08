"""Backend smoke tests for Step 3: real AI providers, image gen, uploads."""
import os
import time
import json
import io
import pytest
import requests

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") if os.environ.get("REACT_APP_BACKEND_URL") else "https://quantum-auth-5.preview.emergentagent.com"


@pytest.fixture(scope="module")
def sess():
    s = requests.Session()
    r = s.post(f"{BASE}/api/auth/login", json={"identifier": "test1@example.com", "password": "Testpass123"})
    if r.status_code != 200:
        # register
        s.post(f"{BASE}/api/auth/register", json={"name": "Test User", "email": "test1@example.com", "password": "Testpass123"})
        r = s.post(f"{BASE}/api/auth/login", json={"identifier": "test1@example.com", "password": "Testpass123"})
    assert r.status_code == 200, r.text
    return s


@pytest.fixture(scope="module")
def conv_id(sess):
    r = sess.post(f"{BASE}/api/conversations", json={"mode": "chat"})
    assert r.status_code == 200
    return r.json()["conversation"]["conv_id"]


@pytest.mark.parametrize("provider", ["chatgpt", "gemini", "claude"])
def test_stream_real_response(sess, provider):
    r = sess.post(f"{BASE}/api/conversations", json={"mode": "chat"})
    cid = r.json()["conversation"]["conv_id"]
    with sess.post(
        f"{BASE}/api/chat/stream",
        json={"conv_id": cid, "provider": provider, "message": "Say hello in one short sentence."},
        stream=True, timeout=60,
    ) as resp:
        assert resp.status_code == 200
        deltas = []
        done = False
        for line in resp.iter_lines():
            if not line:
                continue
            s = line.decode("utf-8")
            if s.startswith("data:"):
                data = json.loads(s[5:].strip())
                if "delta" in data:
                    deltas.append(data["delta"])
                if data.get("done"):
                    done = True
                    break
        text = "".join(deltas)
        assert done, f"stream never completed for {provider}"
        assert len(text) > 5, f"{provider} returned too little: {text!r}"
        assert "not connected" not in text.lower()
    # verify persistence
    g = sess.get(f"{BASE}/api/conversations/{cid}")
    msgs = g.json()["conversation"]["messages"]
    assert len(msgs) >= 2
    assert msgs[-1]["role"] == "assistant"
    assert len(msgs[-1]["content"]) > 5
    # cleanup
    sess.delete(f"{BASE}/api/conversations/{cid}")


def test_upload_txt_and_reject_bad_ext(sess):
    # valid txt
    files = {"file": ("hello.txt", b"secret token is banana42", "text/plain")}
    r = sess.post(f"{BASE}/api/upload", files=files)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["path"].endswith(".txt")
    # reject
    files = {"file": ("bad.exe", b"MZ...", "application/octet-stream")}
    r = sess.post(f"{BASE}/api/upload", files=files)
    assert r.status_code == 400
    assert "Unsupported" in r.json()["detail"]


def test_upload_requires_auth():
    files = {"file": ("hi.txt", b"hi", "text/plain")}
    r = requests.post(f"{BASE}/api/upload", files=files)
    assert r.status_code == 401


def test_image_generation(sess):
    r = sess.post(f"{BASE}/api/conversations", json={"mode": "image"})
    cid = r.json()["conversation"]["conv_id"]
    r = sess.post(f"{BASE}/api/chat/image", json={"conv_id": cid, "prompt": "a tiny blue robot waving"}, timeout=90)
    assert r.status_code == 200, r.text
    a = r.json()["assistant_message"]
    assert a.get("image_url"), f"no image_url: {a}"
    assert a["image_url"].startswith("/api/files/")
    # fetch image
    img = sess.get(f"{BASE}{a['image_url']}")
    assert img.status_code == 200
    assert img.headers.get("content-type", "").startswith("image/")
    assert len(img.content) > 1000
    sess.delete(f"{BASE}/api/conversations/{cid}")


def test_perplexity_rejected(sess):
    r = sess.post(f"{BASE}/api/conversations", json={"mode": "chat"})
    cid = r.json()["conversation"]["conv_id"]
    r = sess.post(f"{BASE}/api/chat/stream", json={"conv_id": cid, "provider": "perplexity", "message": "hi"})
    assert r.status_code == 400
    sess.delete(f"{BASE}/api/conversations/{cid}")


def test_guest_can_chat():
    s = requests.Session()
    r = s.post(f"{BASE}/api/auth/guest")
    assert r.status_code == 200
    r = s.post(f"{BASE}/api/conversations", json={"mode": "chat"})
    cid = r.json()["conversation"]["conv_id"]
    with s.post(f"{BASE}/api/chat/stream", json={"conv_id": cid, "provider": "chatgpt", "message": "Reply with the word OK."}, stream=True, timeout=60) as resp:
        assert resp.status_code == 200
        got = False
        for line in resp.iter_lines():
            if line and line.decode().startswith("data:"):
                data = json.loads(line.decode()[5:].strip())
                if data.get("done"):
                    got = True
                    break
        assert got
    s.delete(f"{BASE}/api/conversations/{cid}")
