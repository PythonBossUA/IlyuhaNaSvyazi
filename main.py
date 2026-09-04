import os
import uuid
import base64
import asyncio

from typing import Annotated

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, status, Depends
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from sqlalchemy import select, update, insert, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

import orjson
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2 import PasswordHasher, Type

from database import get_session
from models import User, Message


# ============================================================
# Константи (кешуються при запуску для швидкодії)
# ============================================================
_DB_KEY = base64.urlsafe_b64decode(os.environ["DATABASE_ENCRYPT_KEY"].encode())
_HKDF_INFO = b"ilyuha-na-svyazi|v1|aes-gcm-256"
_EC_CURVE = ec.SECP256R1()
_EC_ECDH = ec.ECDH()
_SHA256 = hashes.SHA256()
_DB_AES = AESGCM(_DB_KEY)

_ph = PasswordHasher(
    time_cost=3, memory_cost=65536, parallelism=1,
    hash_len=32, salt_len=16, type=Type.ID,
)

# Словник: client_id -> tuple(websocket, aes_key, login)
ws_connections = {}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
DATABASE = Annotated[AsyncSession, Depends(get_session)]


# ============================================================
# Middleware (функціональний, без класу — швидше)
# ============================================================
async def _forwarded_proto_middleware(request: Request, call_next):
    proto = request.headers.get("x-forwarded-proto")
    if proto:
        p = proto.split(",", 1)[0].strip()
        if p in ("http", "https"):
            request.scope["scheme"] = p
    return await call_next(request)

app.middleware("http")(_forwarded_proto_middleware)


# ============================================================
# Base64URL (оптимізовані)
# ============================================================
def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64url_to_int(value: str) -> int:
    return int.from_bytes(
        base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big"
    )


# ============================================================
# ECDH (оптимізовані)
# ============================================================
def generate_private_key():
    return ec.generate_private_key(_EC_CURVE)

def export_public_jwk(private_key):
    pn = private_key.public_key().public_numbers()
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64url_no_padding(pn.x.to_bytes(32, "big")),
        "y": b64url_no_padding(pn.y.to_bytes(32, "big")),
    }

def import_public_jwk(jwk):
    return ec.EllipticCurvePublicNumbers(
        x=b64url_to_int(jwk["x"]),
        y=b64url_to_int(jwk["y"]),
        curve=_EC_CURVE,
    ).public_key()


# ============================================================
# AES key derivation (оптимізовано)
# ============================================================
def derive_aes_key(my_private_key, peer_public_key, salt):
    return HKDF(
        algorithm=_SHA256, length=32, salt=salt, info=_HKDF_INFO,
    ).derive(my_private_key.exchange(_EC_ECDH, peer_public_key))


# ============================================================
# Шифрування / розшифрування (оптимізовані — ascii замість utf-8 де можливо)
# ============================================================
def encrypt_text(key, text, client_id):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(
        nonce, text.encode("utf-8"), f"client_id={client_id}|v=1".encode("ascii")
    )

def encrypt_text_for_database(text):
    nonce = os.urandom(12)
    return nonce + _DB_AES.encrypt(nonce, text.encode("utf-8"), None)

def decrypt_text(key, packet, client_id):
    return AESGCM(key).decrypt(
        packet[:12], packet[12:], f"client_id={client_id}|v=1".encode("ascii")
    ).decode("utf-8")

def decrypt_text_for_database(packet):
    return _DB_AES.decrypt(packet[:12], packet[12:], None).decode("utf-8")


# ============================================================
# Broadcast (оптимізований — orjson, мінімум dict операцій)
# ============================================================
async def broadcast_encrypted(
    message, message_type="encrypted_message", exclude_client_id=None,
    event=None, source_client_id=None, owner=None, extra_data=None,
    secure_message=True,
):
    coros = []
    for cid, conn in ws_connections.items():
        if cid == exclude_client_id:
            continue

        payload = {
            "type": message_type,
            "data": base64.b64encode(
                encrypt_text(conn[1], message, cid)
            ).decode("ascii") if secure_message else message,
        }
        if owner:
            payload["owner"] = owner
        if extra_data:
            payload.update(extra_data)
        if message_type == "system_message":
            if event is not None:
                payload["event"] = event
            if source_client_id is not None:
                payload["client_id"] = source_client_id

        coros.append(conn[0].send_bytes(orjson.dumps(payload)))

    if coros:
        await asyncio.gather(*coros, return_exceptions=True)


# ============================================================
# Password (спрощені)
# ============================================================
def hash_password(password):
    return _ph.hash(password)

def verify_password(hashed, plain):
    try:
        return _ph.verify(hashed, plain)
    except Exception:
        return False


# ============================================================
# Messages (оптимізовані SQL + list comprehension)
# ============================================================
async def get_last_encrypted_messages(database, client_id, key, last_sent_at=None, last_message_id=None):
    limit = 15
    stmt = (
        select(
            Message.id, Message.text, Message.is_changed, User.login,
            func.timezone("Europe/Kyiv", Message.sent_at).label("sent_at"),
            Message.sent_at.label("cursor_sent_at"),
        )
        .join(Message.user)
        .order_by(Message.sent_at.desc(), Message.id.desc())
        .limit(limit + 1)
    )
    if last_sent_at is not None and last_message_id is not None:
        stmt = stmt.where(or_(
            Message.sent_at < last_sent_at,
            and_(Message.sent_at == last_sent_at, Message.id < last_message_id),
        ))

    rows = (await database.execute(stmt)).all()
    has_more = len(rows) > limit
    view_rows = rows[:limit] if has_more else rows

    items = [
        {
            "id": r.id,
            "is_changed": r.is_changed,
            "text": base64.b64encode(
                encrypt_text(key, decrypt_text_for_database(r.text), client_id)
            ).decode("ascii"),
            "login": r.login,
            "sent_at": r.sent_at.isoformat(),
        }
        for r in view_rows
    ]

    nxt_sent = nxt_id = None
    if has_more:
        oldest = rows[limit - 1]
        nxt_sent = oldest.cursor_sent_at
        nxt_id = oldest.id

    return {
        "items": items, "has_more": has_more,
        "last_sent_at": nxt_sent, "last_message_id": nxt_id,
    }


# ============================================================
# Typing (оптимізований)
# ============================================================
async def cancel_typing(login, client_id, timeout=5):
    try:
        if timeout > 0:
            await asyncio.sleep(timeout)
        await broadcast_encrypted(
            message=login, message_type="user_is_not_typing",
            exclude_client_id=client_id,
        )
    except asyncio.CancelledError:
        pass


# ============================================================
# Routes
# ============================================================
@app.head("/")
def render_uptime():
    return

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"client_id": str(uuid.uuid4())})


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, database: DATABASE, client_id: str):
    await websocket.accept()

    client_pub_task = None
    typing_task = None
    registered = False
    ws_user = None

    try:
        # ===== HANDSHAKE =====
        client_pub_task = asyncio.create_task(websocket.receive_bytes())

        server_priv = generate_private_key()
        await websocket.send_bytes(orjson.dumps({
            "type": "public_key", "jwk": export_public_jwk(server_priv)
        }))

        client_pub_json = orjson.loads(await asyncio.wait_for(client_pub_task, timeout=5))
        client_pub_key = import_public_jwk(client_pub_json["jwk"])
        server_aes = derive_aes_key(server_priv, client_pub_key, client_id.encode("ascii"))

        await websocket.send_bytes(orjson.dumps({"type": "handshake_ok"}))

        # ===== AUTHORIZATION =====
        authenticated = False
        while not authenticated:
            auth = orjson.loads(await asyncio.wait_for(websocket.receive_bytes(), timeout=120))

            if auth.get("type") != "authorization" or frozenset(("type","login","password")) != auth.keys():
                await websocket.send_bytes(orjson.dumps({
                    "type": "auth_error",
                    "message": "Невірний формат авторизації" if frozenset(("type","login","password")) != auth.keys()
                    else 'Очікується тип "authorization"'
                }))
                continue

            raw_pw = decrypt_text(server_aes, base64.b64decode(auth["password"]), client_id)
            ws_user = await database.scalar(select(User).where(User.login == auth["login"]))

            if not ws_user:
                await websocket.send_bytes(orjson.dumps({"type": "auth_error", "message": "Кента не знайдено"}))
                continue
            if not verify_password(ws_user.hashed_password, raw_pw):
                await websocket.send_bytes(orjson.dumps({"type": "auth_error", "message": "Хуйовий пароль"}))
                continue

            authenticated = True

        # ===== PASSWORD CHANGE =====
        if ws_user.require_password_change:
            await websocket.send_bytes(orjson.dumps({"type": "need_password_change"}))

            pw_changed = False
            while not pw_changed:
                cd = orjson.loads(await asyncio.wait_for(websocket.receive_bytes(), timeout=300))

                if cd.get("type") != "password_change" or frozenset(("type","new_password")) != cd.keys():
                    await websocket.send_bytes(orjson.dumps({
                        "type": "password_change_error",
                        "message": "Невірний формат зміни пароля" if frozenset(("type","new_password")) != cd.keys()
                        else "Очікується тип password_change"
                    }))
                    continue

                new_pw = decrypt_text(server_aes, base64.b64decode(cd["new_password"]), client_id)
                await database.execute(
                    update(User).where(User.login == ws_user.login).values(
                        hashed_password=hash_password(new_pw), require_password_change=False,
                    )
                )
                await database.commit()
                pw_changed = True

        # ===== REGISTRATION =====
        old = ws_connections.get(client_id)
        if old and old[0] is not websocket:
            try:
                await old[0].close(code=1000)
            except Exception:
                pass

        if any(c[2] == ws_user.login for c in ws_connections.values()):
            await websocket.send_bytes(orjson.dumps({
                "type": "user_already_authorized", "message": "Кабан вже зареєстрований в чаті"
            }))
            return

        # Зберігаємо як tuple: (websocket, aes_key, login) — швидший доступ ніж dict
        ws_connections[client_id] = (websocket, server_aes, ws_user.login)
        registered = True

        # ===== LOAD MESSAGES =====
        lm = await get_last_encrypted_messages(database, client_id, server_aes)
        last_sent_at = lm["last_sent_at"]
        last_msg_id = lm["last_message_id"]
        has_more = lm["has_more"]

        await websocket.send_bytes(orjson.dumps({
            "type": "auth_success", "last_messages": lm["items"], "has_more": has_more,
        }))

        await broadcast_encrypted(
            message=f"Кабан {ws_user.login} залетів в чат",
            message_type="system_message", exclude_client_id=client_id,
            event="connected", source_client_id=client_id,
        )

        # ===== WEBSOCKET CYCLE =====
        while True:
            data = orjson.loads(await websocket.receive_bytes())
            msg_type = data.get("type")

            if msg_type == "encrypted_message":
                message = decrypt_text(server_aes, base64.b64decode(data["data"]), client_id)

                message_id = await database.scalar(
                    insert(Message)
                    .values(text=encrypt_text_for_database(message), user_id=ws_user.id)
                    .returning(Message.id)
                )

                if typing_task and not typing_task.done():
                    typing_task.cancel()
                await cancel_typing(ws_user.login, client_id, timeout=0)
                await database.commit()

                await broadcast_encrypted(
                    message=message, message_type="encrypted_message",
                    exclude_client_id=client_id, owner=ws_user.login,
                    extra_data={"message_id": message_id},
                )

            elif msg_type == "load_encrypted_messages":
                if has_more:
                    om = await get_last_encrypted_messages(
                        database, client_id, server_aes, last_sent_at, last_msg_id
                    )
                    last_sent_at = om["last_sent_at"]
                    last_msg_id = om["last_message_id"]
                    has_more = om["has_more"]
                    await websocket.send_bytes(orjson.dumps({
                        "type": "load_encrypted_messages_success",
                        "has_more": has_more, "messages": om["items"],
                    }))
                    continue

                await websocket.send_bytes(orjson.dumps({
                    "type": "load_encrypted_messages_canceled", "reason": "last messages not found",
                }))

            elif msg_type == "user_is_typing":
                await broadcast_encrypted(
                    message=ws_user.login, message_type="user_is_typing",
                    exclude_client_id=client_id, secure_message=False,
                )
                if typing_task and not typing_task.done():
                    typing_task.cancel()
                typing_task = asyncio.create_task(cancel_typing(ws_user.login, client_id))

            elif msg_type == "change_message":
                new_text = decrypt_text(server_aes, base64.b64decode(data["new_text"]), client_id)
                result = await database.execute(
                    update(Message)
                    .where(
                        Message.user_id == ws_user.id, Message.id == data["message_id"],
                    )
                    .values(
                        text=encrypt_text_for_database(new_text),
                        is_changed=True
                    )
                )
                if result.rowcount == 1:
                    await broadcast_encrypted(
                        message=new_text, message_type="change_message",
                        exclude_client_id=client_id, extra_data={"message_id": data["message_id"]},
                    )
                    await database.commit()
                else:
                    await database.rollback()

    except WebSocketDisconnect:
        pass

    except Exception:
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass

    finally:
        if client_pub_task and not client_pub_task.done():
            client_pub_task.cancel()
        if typing_task and not typing_task.done():
            typing_task.cancel()
        if registered and client_id in ws_connections:
            conn = ws_connections.get(client_id)
            if conn and conn[0] is websocket:
                ws_connections.pop(client_id, None)
                try:
                    await broadcast_encrypted(
                        message=f"Кабан {ws_user.login if ws_user else client_id} с'їбався",
                        message_type="system_message", exclude_client_id=client_id,
                        event="disconnected", source_client_id=client_id,
                    )
                except Exception:
                    pass