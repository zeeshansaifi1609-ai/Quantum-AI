from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import uuid
import json
import base64
import asyncio
import logging
import secrets
from io import BytesIO
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import httpx
import requests
import pypdf
from fastapi import (
    FastAPI,
    APIRouter,
    Request,
    Response,
    HTTPException,
    Depends,
    UploadFile,
    File,
    Form,
)
from fastapi.responses import StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field, field_validator
from emergentintegrations.llm.chat import LlmChat, UserMessage, ImageContent

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("quantum-auth")

app = FastAPI(title="Quantum AI Auth")
api_router = APIRouter(prefix="/api")

SESSION_DAYS = 7
SESSION_COOKIE = "session_token"
EMERGENT_AUTH_SESSION_URL = os.environ.get(
    "EMERGENT_AUTH_SESSION_URL",
    "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
)
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


def public_user(doc: dict) -> dict:
    return {
        "user_id": doc["user_id"],
        "email": doc.get("email"),
        "name": doc.get("name"),
        "picture": doc.get("picture"),
        "role": doc.get("role", "user"),
        "is_guest": doc.get("is_guest", False),
        "auth_provider": doc.get("auth_provider", "email"),
        "created_at": doc.get("created_at"),
    }


async def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(48)
    await db.user_sessions.insert_one(
        {
            "session_token": token,
            "user_id": user_id,
            "created_at": iso(now_utc()),
            "expires_at": iso(now_utc() + timedelta(days=SESSION_DAYS)),
        }
    )
    return token


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=SESSION_DAYS * 24 * 60 * 60,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=SESSION_COOKIE, path="/", samesite="none", secure=True)


def _extract_token(request: Request) -> Optional[str]:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        return token
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


async def get_current_user(request: Request) -> dict:
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = await db.user_sessions.find_one({"session_token": token}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    expires_at = session["expires_at"]
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now_utc():
        await db.user_sessions.delete_one({"session_token": token})
        raise HTTPException(status_code=401, detail="Session expired")
    user = await db.users.find_one({"user_id": session["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ---------------------------------------------------------------------------
# Brute force protection
# ---------------------------------------------------------------------------
async def check_lockout(identifier: str) -> None:
    rec = await db.login_attempts.find_one({"identifier": identifier}, {"_id": 0})
    if not rec:
        return
    if rec.get("count", 0) >= MAX_FAILED_ATTEMPTS:
        last = rec.get("last_attempt")
        if isinstance(last, str):
            last = datetime.fromisoformat(last)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if now_utc() - last < timedelta(minutes=LOCKOUT_MINUTES):
            raise HTTPException(status_code=429, detail="Too many failed attempts. Please try again in 15 minutes.")
        await db.login_attempts.delete_one({"identifier": identifier})


async def record_failed(identifier: str) -> None:
    await db.login_attempts.update_one(
        {"identifier": identifier},
        {"$inc": {"count": 1}, "$set": {"last_attempt": iso(now_utc())}},
        upsert=True,
    )


async def clear_attempts(identifier: str) -> None:
    await db.login_attempts.delete_one({"identifier": identifier})


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class RegisterInput(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Display name is required")
        return v


class LoginInput(BaseModel):
    identifier: str = Field(min_length=1)  # email or display name
    password: str = Field(min_length=1)


class GoogleSessionInput(BaseModel):
    session_id: str


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
@api_router.post("/auth/register")
async def register(payload: RegisterInput, response: Response):
    email = payload.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = {
        "user_id": f"user_{uuid.uuid4().hex[:12]}",
        "email": email,
        "name": payload.name.strip(),
        "password_hash": hash_password(payload.password),
        "picture": None,
        "role": "user",
        "is_guest": False,
        "auth_provider": "email",
        "created_at": iso(now_utc()),
    }
    await db.users.insert_one(user)
    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {"user": public_user(user), "session_token": token}


@api_router.post("/auth/login")
async def login(payload: LoginInput, request: Request, response: Response):
    identifier = payload.identifier.strip()
    ip = request.client.host if request.client else "unknown"
    lock_id = f"{ip}:{identifier.lower()}"
    await check_lockout(lock_id)

    query = {"email": identifier.lower()} if "@" in identifier else {"name": identifier}
    user = await db.users.find_one(query)
    if not user and "@" not in identifier:
        user = await db.users.find_one({"email": identifier.lower()})

    if not user or not user.get("password_hash") or not verify_password(payload.password, user["password_hash"]):
        await record_failed(lock_id)
        raise HTTPException(status_code=401, detail="Invalid credentials. Please check your email/username and password.")

    await clear_attempts(lock_id)
    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {"user": public_user(user), "session_token": token}


@api_router.post("/auth/guest")
async def guest_login(response: Response):
    suffix = uuid.uuid4().hex[:6].upper()
    user = {
        "user_id": f"guest_{uuid.uuid4().hex[:12]}",
        "name": f"Guest-{suffix}",
        "password_hash": None,
        "picture": None,
        "role": "guest",
        "is_guest": True,
        "auth_provider": "guest",
        "created_at": iso(now_utc()),
    }
    await db.users.insert_one(user)
    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {"user": public_user(user), "session_token": token}


class UpgradeInput(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


@api_router.post("/auth/upgrade")
async def upgrade_guest(payload: UpgradeInput, request: Request):
    user = await get_current_user(request)
    if not user.get("is_guest"):
        raise HTTPException(status_code=400, detail="This account is already registered.")
    email = payload.email.lower().strip()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {
            "$set": {
                "email": email,
                "name": payload.name.strip(),
                "password_hash": hash_password(payload.password),
                "is_guest": False,
                "role": "user",
                "auth_provider": "email",
            }
        },
    )
    updated = await db.users.find_one({"user_id": user["user_id"]}, {"_id": 0})
    return {"user": public_user(updated)}


@api_router.post("/auth/google/session")
async def google_session(payload: GoogleSessionInput, response: Response):
    async with httpx.AsyncClient(timeout=15) as http:
        resp = await http.get(EMERGENT_AUTH_SESSION_URL, headers={"X-Session-ID": payload.session_id})
    if resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Google sign-in failed. Please try again.")
    data = resp.json()
    email = (data.get("email") or "").lower().strip()
    if not email:
        raise HTTPException(status_code=401, detail="Google sign-in did not return an email.")

    user = await db.users.find_one({"email": email})
    if not user:
        user = {
            "user_id": f"user_{uuid.uuid4().hex[:12]}",
            "email": email,
            "name": data.get("name") or email.split("@")[0],
            "password_hash": None,
            "picture": data.get("picture"),
            "role": "user",
            "is_guest": False,
            "auth_provider": "google",
            "created_at": iso(now_utc()),
        }
        await db.users.insert_one(user)
    else:
        await db.users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"name": data.get("name") or user.get("name"), "picture": data.get("picture") or user.get("picture")}},
        )
        user = await db.users.find_one({"user_id": user["user_id"]}, {"_id": 0})

    token = await create_session(user["user_id"])
    set_session_cookie(response, token)
    return {"user": public_user(user), "session_token": token}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": public_user(user)}


@api_router.post("/auth/logout")
async def logout(request: Request, response: Response):
    token = _extract_token(request)
    if token:
        await db.user_sessions.delete_one({"session_token": token})
    clear_session_cookie(response)
    return {"success": True}


@api_router.get("/")
async def root():
    return {"message": "Quantum AI Auth API"}


# ---------------------------------------------------------------------------
# Conversations (per-user; messages persisted for sidebar history)
# ---------------------------------------------------------------------------
class ConversationCreate(BaseModel):
    title: Optional[str] = None
    mode: Optional[str] = "chat"


class ConversationUpdate(BaseModel):
    title: Optional[str] = None
    messages: Optional[list] = None


def public_conversation(doc: dict, with_messages: bool = True) -> dict:
    out = {
        "conv_id": doc["conv_id"],
        "title": doc.get("title", "New chat"),
        "mode": doc.get("mode", "chat"),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }
    if with_messages:
        out["messages"] = doc.get("messages", [])
    return out


@api_router.get("/conversations")
async def list_conversations(user: dict = Depends(get_current_user)):
    docs = (
        await db.conversations.find({"user_id": user["user_id"]}, {"_id": 0, "messages": 0})
        .sort("updated_at", -1)
        .to_list(500)
    )
    return {"conversations": docs}


@api_router.post("/conversations")
async def create_conversation(payload: ConversationCreate, user: dict = Depends(get_current_user)):
    conv = {
        "conv_id": f"conv_{uuid.uuid4().hex[:12]}",
        "user_id": user["user_id"],
        "title": payload.title or "New chat",
        "mode": payload.mode or "chat",
        "messages": [],
        "created_at": iso(now_utc()),
        "updated_at": iso(now_utc()),
    }
    await db.conversations.insert_one(conv)
    return {"conversation": public_conversation(conv)}


@api_router.get("/conversations/{conv_id}")
async def get_conversation(conv_id: str, user: dict = Depends(get_current_user)):
    doc = await db.conversations.find_one(
        {"conv_id": conv_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"conversation": public_conversation(doc)}


@api_router.patch("/conversations/{conv_id}")
async def update_conversation(conv_id: str, payload: ConversationUpdate, user: dict = Depends(get_current_user)):
    updates = {"updated_at": iso(now_utc())}
    if payload.title is not None:
        updates["title"] = payload.title[:80]
    if payload.messages is not None:
        updates["messages"] = payload.messages[-200:]
    result = await db.conversations.update_one(
        {"conv_id": conv_id, "user_id": user["user_id"]}, {"$set": updates}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"success": True}


@api_router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, user: dict = Depends(get_current_user)):
    result = await db.conversations.delete_one({"conv_id": conv_id, "user_id": user["user_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"success": True}


@api_router.delete("/conversations")
async def delete_all_conversations(user: dict = Depends(get_current_user)):
    result = await db.conversations.delete_many({"user_id": user["user_id"]})
    return {"success": True, "deleted": result.deleted_count}


# ---------------------------------------------------------------------------
# AI Providers + Object Storage (Step 3)
# ---------------------------------------------------------------------------
EMERGENT_LLM_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = "quantum-ai"
STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
_storage_key = None

# Text providers -> (provider, model). Perplexity intentionally excluded.
TEXT_MODELS = {
    "chatgpt": ("openai", "gpt-5.4"),
    "gemini": ("gemini", "gemini-3.1-pro-preview"),
    "claude": ("anthropic", "claude-sonnet-4-6"),
}
IMAGE_MODEL = ("gemini", "gemini-3.1-flash-image-preview")

MIME_TYPES = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
    "gif": "image/gif", "webp": "image/webp", "pdf": "application/pdf",
    "txt": "text/plain", "csv": "text/csv", "json": "application/json",
}
ALLOWED_UPLOAD_EXT = {"png", "jpg", "jpeg", "webp", "gif", "pdf", "txt"}


def init_storage(force: bool = False):
    global _storage_key
    if _storage_key and not force:
        return _storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_LLM_KEY}, timeout=30)
    resp.raise_for_status()
    _storage_key = resp.json()["storage_key"]
    return _storage_key


def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data,
        timeout=120,
    )
    if resp.status_code == 404:
        key = init_storage(force=True)
        resp = requests.put(
            f"{STORAGE_URL}/objects/{path}",
            headers={"X-Storage-Key": key, "Content-Type": content_type},
            data=data,
            timeout=120,
        )
    resp.raise_for_status()
    return resp.json()


def get_object(path: str):
    key = init_storage()
    resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    if resp.status_code == 404:
        key = init_storage(force=True)
        resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")


class ChatStreamInput(BaseModel):
    conv_id: str
    provider: str = "chatgpt"
    message: str
    attachments: list = []
    regenerate: bool = False


class QuantumInput(BaseModel):
    conv_id: str
    message: str
    attachments: list = []
    regenerate: bool = False


class ImageGenInput(BaseModel):
    conv_id: str
    prompt: str


def _system_prompt(provider_name: str, history: list) -> str:
    base = (
        f"You are Quantum AI, a premium multi-model AI assistant currently responding as the "
        f"{provider_name} model. Be helpful, clear and accurate. Use markdown when useful."
    )
    if not history:
        return base
    lines = []
    for m in history[-12:]:
        role = "User" if m.get("role") == "user" else "Assistant"
        content = (m.get("content") or "").strip()
        if content:
            lines.append(f"{role}: {content}")
    if not lines:
        return base
    return base + "\n\nConversation so far:\n" + "\n".join(lines)


async def _build_image_contents(attachments: list) -> list:
    contents = []
    for att in attachments or []:
        ctype = att.get("content_type", "")
        if ctype.startswith("image/"):
            try:
                data, _ = get_object(att["path"])
                contents.append(ImageContent(base64.b64encode(data).decode("utf-8")))
            except Exception:
                pass
    return contents


async def _attachment_text(attachments: list) -> str:
    extra = ""
    for att in attachments or []:
        ctype = att.get("content_type", "")
        name = att.get("name", "file")
        if ctype in ("text/plain", "text/csv", "application/json"):
            try:
                data, _ = get_object(att["path"])
                extra += f"\n\n[Attached file: {name}]\n{data.decode('utf-8', errors='ignore')[:8000]}"
            except Exception:
                pass
        elif ctype == "application/pdf":
            try:
                data, _ = get_object(att["path"])
                reader = pypdf.PdfReader(BytesIO(data))
                pages = []
                for page in reader.pages[:20]:
                    pages.append(page.extract_text() or "")
                text = "\n".join(pages).strip()
                if text:
                    extra += f"\n\n[Attached PDF: {name}]\n{text[:12000]}"
                else:
                    extra += f"\n\n[Attached PDF: {name} — no extractable text found]"
            except Exception as e:
                logger.warning("PDF extract failed for %s: %s", name, e)
                extra += f"\n\n[Attached PDF: {name} — could not read content]"
    return extra


@api_router.post("/chat/stream")
async def chat_stream(payload: ChatStreamInput, request: Request):
    user = await get_current_user(request)
    conv = await db.conversations.find_one(
        {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if payload.provider not in TEXT_MODELS:
        raise HTTPException(status_code=400, detail="Unknown provider")

    history = conv.get("messages", [])
    provider_key = payload.provider
    provider_label = {"chatgpt": "ChatGPT", "gemini": "Gemini", "claude": "Claude"}[provider_key]
    provider, model = TEXT_MODELS[provider_key]

    # In-place regenerate: drop the trailing assistant turn and reuse the last user message.
    reused_attachments = payload.attachments or []
    if payload.regenerate:
        if history and history[-1].get("role") == "assistant":
            history = history[:-1]
        if history and history[-1].get("role") == "user":
            last_user = history[-1]
            history = history[:-1]
            reused_attachments = last_user.get("attachments", []) or []

    user_msg = {
        "id": f"msg_{uuid.uuid4().hex[:10]}",
        "role": "user",
        "content": payload.message,
        "model": provider_key,
        "attachments": reused_attachments,
        "created_at": iso(now_utc()),
    }

    image_contents = await _build_image_contents(reused_attachments)
    doc_text = await _attachment_text(reused_attachments)

    chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=payload.conv_id,
        system_message=_system_prompt(provider_label, history),
    ).with_model(provider, model)

    um = UserMessage(text=payload.message + doc_text, file_contents=image_contents or None)

    async def event_generator():
        assistant_text = ""
        try:
            from emergentintegrations.llm.chat import TextDelta, StreamDone
            async for event in chat.stream_message(um):
                if isinstance(event, TextDelta):
                    assistant_text += event.content
                    yield f"data: {json.dumps({'delta': event.content})}\n\n"
                elif isinstance(event, StreamDone):
                    break
        except Exception as e:
            logger.error("Chat stream error: %s", e)
            if not assistant_text:
                assistant_text = "I ran into an issue generating a response. Please try again."
                yield f"data: {json.dumps({'delta': assistant_text})}\n\n"

        assistant_msg = {
            "id": f"msg_{uuid.uuid4().hex[:10]}",
            "role": "assistant",
            "content": assistant_text,
            "model": provider_key,
            "created_at": iso(now_utc()),
        }
        new_messages = history + [user_msg, assistant_msg]
        update = {"messages": new_messages[-200:], "updated_at": iso(now_utc())}
        if len(history) == 0:
            update["title"] = payload.message[:60]
        await db.conversations.update_one(
            {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"$set": update}
        )
        yield f"data: {json.dumps({'done': True, 'message_id': assistant_msg['id']})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


async def _one_answer(session_id: str, provider: str, model: str, label: str, text: str) -> str:
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"{session_id}-{provider}",
            system_message=f"You are {label}. Answer the user's prompt helpfully and concisely.",
        ).with_model(provider, model)
        return await chat.send_message(UserMessage(text=text))
    except Exception as e:
        logger.error("Quantum sub-answer (%s) failed: %s", provider, str(e)[:150])
        return "(No response available from this model.)"


@api_router.post("/chat/quantum")
async def chat_quantum(payload: QuantumInput, request: Request):
    user = await get_current_user(request)
    conv = await db.conversations.find_one(
        {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    history = conv.get("messages", [])
    reused_attachments = payload.attachments or []
    if payload.regenerate:
        if history and history[-1].get("role") == "assistant":
            history = history[:-1]
        if history and history[-1].get("role") == "user":
            last_user = history[-1]
            history = history[:-1]
            reused_attachments = last_user.get("attachments", []) or []

    doc_text = await _attachment_text(reused_attachments)
    prompt = payload.message + doc_text

    user_msg = {
        "id": f"msg_{uuid.uuid4().hex[:10]}",
        "role": "user",
        "content": payload.message,
        "model": "quantum",
        "attachments": reused_attachments,
        "created_at": iso(now_utc()),
    }

    # Run the three models in parallel.
    results = await asyncio.gather(
        _one_answer(payload.conv_id, "openai", "gpt-5.4", "ChatGPT", prompt),
        _one_answer(payload.conv_id, "gemini", "gemini-3.1-pro-preview", "Gemini", prompt),
        _one_answer(payload.conv_id, "anthropic", "claude-sonnet-4-6", "Claude", prompt),
    )
    sources = [
        {"model": "chatgpt", "name": "ChatGPT", "content": results[0]},
        {"model": "gemini", "name": "Gemini", "content": results[1]},
        {"model": "claude", "name": "Claude", "content": results[2]},
    ]

    synth_system = (
        "You are Quantum AI's synthesis engine. You are given three independent answers "
        "(from ChatGPT, Gemini and Claude) to the same user prompt. Produce ONE superior, unified "
        "answer that combines their strengths, resolves contradictions, and stays clear and concise. "
        "Do not mention the individual models by name unless it genuinely helps the user."
    )
    synth_input = (
        f"User prompt:\n{payload.message}\n\n"
        f"ChatGPT answer:\n{results[0]}\n\n"
        f"Gemini answer:\n{results[1]}\n\n"
        f"Claude answer:\n{results[2]}\n\n"
        "Now write the single best unified answer."
    )
    synth_chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=f"{payload.conv_id}-synth",
        system_message=synth_system,
    ).with_model("anthropic", "claude-sonnet-4-6")

    async def event_generator():
        assistant_text = ""
        # send sources first so the UI can show the per-model panel immediately
        yield f"data: {json.dumps({'sources': sources})}\n\n"
        try:
            from emergentintegrations.llm.chat import TextDelta, StreamDone
            async for event in synth_chat.stream_message(UserMessage(text=synth_input)):
                if isinstance(event, TextDelta):
                    assistant_text += event.content
                    yield f"data: {json.dumps({'delta': event.content})}\n\n"
                elif isinstance(event, StreamDone):
                    break
        except Exception as e:
            logger.error("Quantum synth error: %s", str(e)[:150])
            if not assistant_text:
                assistant_text = "\n\n".join(f"**{s['name']}**\n{s['content']}" for s in sources)
                yield f"data: {json.dumps({'delta': assistant_text})}\n\n"

        assistant_msg = {
            "id": f"msg_{uuid.uuid4().hex[:10]}",
            "role": "assistant",
            "content": assistant_text,
            "model": "quantum",
            "sources": sources,
            "created_at": iso(now_utc()),
        }
        new_messages = history + [user_msg, assistant_msg]
        update = {"messages": new_messages[-200:], "updated_at": iso(now_utc()), "mode": "quantum"}
        if len(history) == 0:
            update["title"] = payload.message[:60]
        await db.conversations.update_one(
            {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"$set": update}
        )
        yield f"data: {json.dumps({'done': True, 'sources': sources})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@api_router.post("/chat/image")
async def chat_image(payload: ImageGenInput, request: Request):
    user = await get_current_user(request)
    conv = await db.conversations.find_one(
        {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"_id": 0}
    )
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    history = conv.get("messages", [])
    user_msg = {
        "id": f"msg_{uuid.uuid4().hex[:10]}",
        "role": "user",
        "content": payload.prompt,
        "model": "image",
        "attachments": [],
        "created_at": iso(now_utc()),
    }

    provider, model = IMAGE_MODEL
    chat = LlmChat(
        api_key=EMERGENT_LLM_KEY,
        session_id=payload.conv_id,
        system_message="You are Quantum AI's image generation engine.",
    ).with_model(provider, model).with_params(modalities=["image", "text"])

    image_url = None
    text_out = ""
    error = None
    try:
        text_out, images = await chat.send_message_multimodal_response(
            UserMessage(text=payload.prompt)
        )
        if images:
            img = images[0]
            ext = "png"
            img_bytes = base64.b64decode(img["data"])
            path = f"{APP_NAME}/generated/{user['user_id']}/{uuid.uuid4().hex}.{ext}"
            put_object(path, img_bytes, img.get("mime_type", "image/png"))
            image_url = f"/api/files/{path}"
    except Exception as e:
        logger.error("Image gen error: %s", str(e)[:200])
        error = "Image generation failed. Please try again."

    assistant_msg = {
        "id": f"msg_{uuid.uuid4().hex[:10]}",
        "role": "assistant",
        "content": text_out if not error else error,
        "model": "image",
        "image_url": image_url,
        "status": "error" if error else None,
        "created_at": iso(now_utc()),
    }
    new_messages = history + [user_msg, assistant_msg]
    update = {"messages": new_messages[-200:], "updated_at": iso(now_utc()), "mode": "image"}
    if len(history) == 0:
        update["title"] = payload.prompt[:60]
    await db.conversations.update_one(
        {"conv_id": payload.conv_id, "user_id": user["user_id"]}, {"$set": update}
    )
    return {"user_message": user_msg, "assistant_message": assistant_msg}


@api_router.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    user = await get_current_user(request)
    ext = (file.filename.rsplit(".", 1)[-1] if "." in file.filename else "").lower()
    if ext not in ALLOWED_UPLOAD_EXT:
        raise HTTPException(status_code=400, detail="Unsupported file type.")
    data = await file.read()
    if len(data) > 15 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large (max 15MB).")
    content_type = file.content_type or MIME_TYPES.get(ext, "application/octet-stream")
    path = f"{APP_NAME}/uploads/{user['user_id']}/{uuid.uuid4().hex}.{ext}"
    put_object(path, data, content_type)
    await db.files.insert_one(
        {
            "file_id": str(uuid.uuid4()),
            "user_id": user["user_id"],
            "storage_path": path,
            "original_filename": file.filename,
            "content_type": content_type,
            "size": len(data),
            "is_deleted": False,
            "created_at": iso(now_utc()),
        }
    )
    return {"path": path, "name": file.filename, "content_type": content_type, "url": f"/api/files/{path}"}


@api_router.get("/files/{path:path}")
async def serve_file(path: str, request: Request):
    user = await get_current_user(request)
    # Ownership: uploaded & generated paths embed the owner's user_id (…/{user_id}/…).
    record = await db.files.find_one({"storage_path": path, "is_deleted": False}, {"_id": 0})
    owns_by_record = record and record.get("user_id") == user["user_id"]
    owns_by_path = f"/{user['user_id']}/" in f"/{path}"
    if not owns_by_record and not owns_by_path:
        raise HTTPException(status_code=403, detail="Not authorized to access this file")
    data, content_type = get_object(path)
    ct = record.get("content_type", content_type) if record else content_type
    return Response(content=data, media_type=ct)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
async def seed_admin():
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@quantumai.app").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    existing = await db.users.find_one({"email": admin_email})
    if existing is None:
        await db.users.insert_one(
            {
                "user_id": f"user_{uuid.uuid4().hex[:12]}",
                "email": admin_email,
                "name": "Quantum Admin",
                "password_hash": hash_password(admin_password),
                "picture": None,
                "role": "admin",
                "is_guest": False,
                "auth_provider": "email",
                "created_at": iso(now_utc()),
            }
        )
        logger.info("Seeded admin user %s", admin_email)
    elif not verify_password(admin_password, existing.get("password_hash", "")):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})
        logger.info("Updated admin password for %s", admin_email)


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("user_id", unique=True)
    # Drop any legacy email index (e.g. sparse) before recreating as a partial unique index.
    try:
        existing = await db.users.index_information()
        if "email_1" in existing and not existing["email_1"].get("partialFilterExpression"):
            await db.users.drop_index("email_1")
    except Exception:
        pass
    await db.users.create_index(
        "email", unique=True, partialFilterExpression={"email": {"$type": "string"}}
    )
    await db.user_sessions.create_index("session_token", unique=True)
    await db.login_attempts.create_index("identifier")
    await db.conversations.create_index([("user_id", 1), ("updated_at", -1)])
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception as e:
        logger.error("Storage init failed: %s", e)
    await seed_admin()


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)
