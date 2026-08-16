import os
import uuid
import base64
import asyncio
from datetime import datetime
from typing import Annotated

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, status, Depends
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from sqlalchemy import select, update, insert, func, or_, and_

from sqlalchemy.ext.asyncio import AsyncSession
from database import get_session
from models import User, Message

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2 import PasswordHasher, Type
from argon2.exceptions import (
    HashingError,
    InvalidHashError,
    VerifyMismatchError,
    VerificationError,
)


class ForwardedProtoMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            for name, value in scope.get("headers", []):
                if name == b"x-forwarded-proto":
                    proto = value.decode("latin-1").split(",")[0].strip()
                    if proto in ("http", "https"):
                        scope = dict(scope)
                        scope["scheme"] = proto
                    break
        await self.app(scope, receive, send)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(ForwardedProtoMiddleware)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

DATABASE = Annotated[AsyncSession, Depends(get_session)]
DB_AES = AESGCM(base64.urlsafe_b64decode(os.environ["DATABASE_ENCRYPT_KEY"].encode()))

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

ws_connections: dict[str, dict] = {}


# ============================================================
# Base64URL утиліти
# ============================================================


def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_to_int(value: str) -> int:
    value += "=" * (-len(value) % 4)
    data = base64.urlsafe_b64decode(value)
    return int.from_bytes(data, "big")


# ============================================================
# ECDH ключі
# ============================================================


def generate_private_key():
    return ec.generate_private_key(ec.SECP256R1())


def export_public_jwk(private_key):
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_no_padding(public_numbers.x.to_bytes(32, "big")),
        "y": b64url_no_padding(public_numbers.y.to_bytes(32, "big")),
    }


def import_public_jwk(jwk: dict):
    if jwk.get("kty") != "EC":
        raise ValueError("Неправильний kty. Очікується EC.")

    if jwk.get("crv") != "P-256":
        raise ValueError("Неправильний crv. Очікується P-256.")

    x = b64url_to_int(jwk["x"])
    y = b64url_to_int(jwk["y"])

    public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())

    return public_numbers.public_key()


# ============================================================
# Виведення AES-ключа
# ============================================================


def derive_aes_key(my_private_key, peer_public_key, salt: bytes, info: bytes) -> bytes:
    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# ============================================================
# Шифрування / розшифрування
# ============================================================


def encrypt_text(key: bytes, text: str, client_id: str) -> bytes:
    nonce = os.urandom(12)
    aad = f"client_id={client_id}|v=1".encode()
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, text.encode(), aad)
    return nonce + ciphertext


def encrypt_text_for_database(text: str) -> bytes:
    nonce = os.urandom(12)
    ciphertext = DB_AES.encrypt(nonce, text.encode(), associated_data=None)
    return nonce + ciphertext


def decrypt_text(key: bytes, packet: bytes, client_id: str) -> str:
    nonce = packet[:12]
    ciphertext = packet[12:]
    aad = f"client_id={client_id}|v=1".encode()
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()


def decrypt_text_for_database(packet: bytes) -> str:
    nonce = packet[:12]
    ciphertext = packet[12:]
    return DB_AES.decrypt(nonce, ciphertext, associated_data=None).decode()


# ============================================================
# Broadcast
# ============================================================


async def broadcast_encrypted(
    message: str,
    message_type: str = "encrypted_message",
    exclude_client_id: str = None,
    event: str = None,
    source_client_id: str = None,
    owner: str = None,
):
    coroutines = []
    for client_id, connection in list(ws_connections.items()):
        if client_id == exclude_client_id:
            continue

        encrypted = encrypt_text(connection["aes_key"], message, client_id)

        payload = {"type": message_type, "data": base64.b64encode(encrypted).decode()}

        if owner:
            payload["owner"] = owner

        if message_type == "system_message":
            if event is not None:
                payload["event"] = event
            if source_client_id is not None:
                payload["client_id"] = source_client_id

        coroutines.append(connection["ws"].send_json(payload))

    await asyncio.gather(*coroutines, return_exceptions=True)


# ============================================================
# Password Hashers
# ============================================================
def hash_password(password: str) -> str:
    try:
        return ph.hash(password)
    except HashingError as e:
        raise ValueError(f"Не вдалося захешувати пароль: {e}")


def verify_password(hashed_password: str, plain_password: str) -> bool:
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ============================================================
# Messages Select
# ============================================================
async def get_last_encrypted_messages(
    database: AsyncSession,
    client_id: int,
    key: bytes,
    last_sent_at: datetime | None = None,
    last_message_id: int | None = None,
) -> dict:
    limit = 15

    stmt = (
        select(
            Message.text,
            User.login,
            func.timezone("Europe/Kyiv", Message.sent_at).label("sent_at"),
            Message.id.label("cursor_message_id"),
            Message.sent_at.label("cursor_sent_at"),
        )
        .join(Message.user)
        .order_by(Message.sent_at.desc(), Message.id.desc())
        .limit(limit + 1)
    )

    if last_sent_at is not None and last_message_id is not None:
        stmt = stmt.where(
            or_(
                Message.sent_at < last_sent_at,
                and_(
                    Message.sent_at == last_sent_at,
                    Message.id < last_message_id,
                ),
            )
        )

    rows = (await database.execute(stmt)).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    items = [
        {
            "text": base64.b64encode(
                encrypt_text(key, decrypt_text_for_database(row.text), client_id)
            ).decode(),
            "login": row.login,
            "sent_at": row.sent_at.isoformat(),
        }
        for row in rows
    ]

    next_last_sent_at = None
    next_last_message_id = None
    if has_more:
        oldest = rows[-1]

        next_last_sent_at = oldest.cursor_sent_at
        next_last_message_id = oldest.cursor_message_id

    return {
        "items": items,
        "has_more": has_more,
        "last_sent_at": next_last_sent_at,
        "last_message_id": next_last_message_id,
    }


# ============================================================
# Routes
# ============================================================


@app.head("/")
def render_uptime():
    return


@app.get("/")
async def index(request: Request):
    client_id = str(uuid.uuid4())

    return templates.TemplateResponse(request, "index.html", {"client_id": client_id})


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, database: DATABASE, client_id: str):
    await websocket.accept()

    client_public_json__task = None
    registered = False

    try:
        # ============================================================
        # HANDSHAKE
        # ============================================================
        client_public_json__task = asyncio.create_task(websocket.receive_json())

        server_private_key = generate_private_key()
        server_public_jwk = export_public_jwk(server_private_key)

        await websocket.send_json({"type": "public_key", "jwk": server_public_jwk})

        client_public_json = await asyncio.wait_for(client_public_json__task, timeout=5)

        if not isinstance(client_public_json, dict):
            raise ValueError("Invalid handshake message")

        if client_public_json.get("type") != "public_key":
            raise ValueError("Expected public_key message")

        client_public_jwk = client_public_json.get("jwk")

        if not isinstance(client_public_jwk, dict):
            raise ValueError("Missing JWK")

        client_public_key = import_public_jwk(client_public_jwk)

        salt = client_id.encode()
        info = b"ilyuha-na-svyazi|v1|aes-gcm-256"

        server_aes_key = derive_aes_key(
            server_private_key, client_public_key, salt, info
        )

        await websocket.send_json({"type": "handshake_ok"})

        # ============================================================
        # AUTHORIZATION
        # ============================================================
        authenticated = False
        ws_user = None

        while not authenticated:
            auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=120)

            if not isinstance(auth_data, dict):
                await websocket.send_json(
                    {"type": "auth_error", "message": "Невірний формат запиту"}
                )
                continue

            if frozenset(("type", "login", "password")) != auth_data.keys():
                await websocket.send_json(
                    {"type": "auth_error", "message": "Невірний формат авторизації"}
                )
                continue

            if auth_data["type"] != "authorization":
                await websocket.send_json(
                    {"type": "auth_error", "message": 'Очікується тип "authorization"'}
                )
                continue

            try:
                raw_password = decrypt_text(
                    packet=base64.b64decode(auth_data["password"]),
                    key=server_aes_key,
                    client_id=client_id,
                )

                ws_user = await database.scalar(
                    select(User).where(User.login == auth_data["login"])
                )

                if not ws_user:
                    await websocket.send_json(
                        {"type": "auth_error", "message": "Користувача не знайдено"}
                    )
                    continue

                if not verify_password(ws_user.hashed_password, raw_password):
                    await websocket.send_json(
                        {"type": "auth_error", "message": "Невірний пароль"}
                    )
                    continue

                authenticated = True

            except Exception:
                await websocket.send_json(
                    {"type": "auth_error", "message": "Помилка обробки запиту"}
                )
                continue

        # ============================================================
        # PASSWORD CHANGE
        # ============================================================
        if ws_user.require_password_change:
            await websocket.send_json(
                {
                    "type": "need_password_change",
                }
            )

            password_changed = False
            while not password_changed:
                change_data = await asyncio.wait_for(
                    websocket.receive_json(), timeout=300
                )

                if not isinstance(change_data, dict):
                    await websocket.send_json(
                        {
                            "type": "password_change_error",
                            "message": "Невірний формат запиту",
                        }
                    )
                    continue

                if frozenset(("type", "new_password")) != change_data.keys():
                    await websocket.send_json(
                        {
                            "type": "password_change_error",
                            "message": "Невірний формат зміни пароля",
                        }
                    )
                    continue

                if change_data["type"] != "password_change":
                    await websocket.send_json(
                        {
                            "type": "password_change_error",
                            "message": "Очікується тип password_change",
                        }
                    )
                    continue

                try:
                    new_raw_password = decrypt_text(
                        packet=base64.b64decode(change_data["new_password"]),
                        key=server_aes_key,
                        client_id=client_id,
                    )

                    await database.execute(
                        update(User)
                        .where(User.login == ws_user.login)
                        .values(
                            hashed_password=hash_password(new_raw_password),
                            require_password_change=False,
                        )
                    )
                    await database.commit()
                    password_changed = True

                except Exception:
                    await websocket.send_json(
                        {
                            "type": "password_change_error",
                            "message": "Помилка зміни пароля",
                        }
                    )
                    continue

        # ============================================================
        # REGISTRATION
        # ============================================================
        old_ws = ws_connections.get(client_id)
        if old_ws:
            old_connection = old_ws["ws"]
            if old_connection is not websocket:
                try:
                    await old_connection.close(code=1000)
                except Exception:
                    pass

        if next(
            (
                ws_data
                for ws_data in ws_connections.values()
                if ws_data["login"] == ws_user.login
            ),
            None,
        ):
            try:
                await websocket.close(code=1008, reason="User already registered")
                return
            except Exception:
                pass

        ws_connections[client_id] = {
            "ws": websocket,
            "aes_key": server_aes_key,
            "login": ws_user.login,
        }
        registered = True

        # ============================================================
        # LOAD LAST MESSAGES
        # ============================================================
        last_messages = await get_last_encrypted_messages(
            database, key=server_aes_key, client_id=client_id
        )

        last_sent_at = last_messages["last_sent_at"]
        last_message_id = last_messages["last_message_id"]
        has_more = last_messages["has_more"]

        await websocket.send_json(
            {
                "type": "auth_success",
                "last_messages": last_messages["items"],
                "has_more": has_more,
            }
        )

        await broadcast_encrypted(
            message=f"Client {ws_user.login} connected",
            message_type="system_message",
            exclude_client_id=client_id,
            event="connected",
            source_client_id=client_id,
        )

        # ============================================================
        # WEBSOCKET CYCLE
        # ============================================================
        while True:
            data = await websocket.receive_json()

            if not isinstance(data, dict):
                raise ValueError("Invalid message format")

            if data.get("type") == "encrypted_message":
                if not isinstance(data.get("data"), str):
                    raise ValueError("Invalid message data")

                packet = base64.b64decode(data["data"])
                message = decrypt_text(server_aes_key, packet, client_id)

                await database.execute(
                    insert(Message).values(
                        text=encrypt_text_for_database(message), user_id=ws_user.id
                    )
                )
                await database.commit()

                await broadcast_encrypted(
                    message=message,
                    message_type="encrypted_message",
                    exclude_client_id=client_id,
                    owner=ws_user.login,
                )
            elif data.get("type") == "load_encrypted_messages":
                """
                receive {
                    "type": "load_encrypted_messages"
                }
                """
                if has_more:
                    old_messages = await get_last_encrypted_messages(
                        database,
                        key=server_aes_key,
                        client_id=client_id,
                        last_sent_at=last_sent_at,
                        last_message_id=last_message_id,
                    )
                    last_sent_at = old_messages["last_sent_at"]
                    last_message_id = old_messages["last_message_id"]
                    has_more = old_messages["has_more"]

                    await websocket.send_json(
                        {
                            "type": "load_encrypted_messages_success",
                            "has_more": has_more,
                            "messages": old_messages["items"],
                        }
                    )
                    continue

                await websocket.send_json(
                    {
                        "type": "load_encrypted_messages_canceled",
                        "reason": "last messages not found",
                    }
                )
            else:
                raise ValueError("Invalid message type")

    except WebSocketDisconnect:
        pass

    except Exception as e:
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass

    finally:
        if client_public_json__task is not None and not client_public_json__task.done():
            client_public_json__task.cancel()

        if registered and ws_connections.get(client_id):
            if ws_connections[client_id]["ws"] is websocket:
                ws_connections.pop(client_id, None)

                try:
                    await broadcast_encrypted(
                        message=f"Client {client_id} disconnected",
                        message_type="system_message",
                        exclude_client_id=client_id,
                        event="disconnected",
                        source_client_id=client_id,
                    )
                except Exception:
                    pass
