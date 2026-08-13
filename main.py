import os
import uuid
import base64
import asyncio
from typing import Annotated

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, status, Depends
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update, delete, insert

from sqlalchemy.ext.asyncio import AsyncSession
from database import get_session
from models import User

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

app = FastAPI()
templates = Jinja2Templates(directory="templates")
DATABASE = Annotated[AsyncSession, Depends(get_session)]

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
    ciphertext = aes.encrypt(nonce, text.encode("utf-8"), aad)
    return nonce + ciphertext


def decrypt_text(key: bytes, packet: bytes, client_id: str) -> str:
    nonce = packet[:12]
    ciphertext = packet[12:]
    aad = f"client_id={client_id}|v=1".encode()
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")


# ============================================================
# Broadcast
# ============================================================


async def broadcast_encrypted(
    message: str,
    message_type: str = "encrypted_message",
    exclude_client_id: str = None,
    event: str = None,
    source_client_id: str = None,
):
    for client_id, connection in list(ws_connections.items()):
        if client_id == exclude_client_id:
            continue

        try:
            encrypted = encrypt_text(connection["aes_key"], message, client_id)

            payload = {
                "type": message_type,
                "data": base64.b64encode(encrypted).decode(),
            }

            if message_type == "system_message":
                if event is not None:
                    payload["event"] = event
                if source_client_id is not None:
                    payload["client_id"] = source_client_id

            await connection["ws"].send_json(payload)

        except Exception:
            pass


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
        """
        receive {
            "type": "authorization",
            "login": "not-encrypted-login",
            "password": "base64(encrypted-aeskey-password)"
        }
        """
        authenticated = False
        ws_user = None

        while not authenticated:
            auth_data = await asyncio.wait_for(websocket.receive_json(), timeout=120)

            if not isinstance(auth_data, dict):
                await websocket.send_json({
                    "type": "auth_error",
                    "message": "Невірний формат запиту"
                })
                continue

            if frozenset(("type", "login", "password")) != auth_data.keys():
                await websocket.send_json({
                    "type": "auth_error",
                    "message": "Невірний формат авторизації"
                })
                continue

            if auth_data["type"] != "authorization":
                await websocket.send_json({
                    "type": "auth_error",
                    "message": "Очікується тип \"authorization\""
                })
                continue

            try:
                raw_password = decrypt_text(
                    packet=base64.b64decode(auth_data["password"]),
                    key=server_aes_key,
                    client_id=client_id,
                )

                ws_user = await database.scalar(
                    select(User)
                    .where(
                        User.login == auth_data["login"]
                    )
                )

                if not ws_user:
                    await websocket.send_json({
                        "type": "auth_error",
                        "message": "Користувача не знайдено"
                    })
                    continue

                if not verify_password(ws_user.hashed_password, raw_password):
                    await websocket.send_json({
                        "type": "auth_error",
                        "message": "Невірний пароль"
                    })
                    continue

                authenticated = True

            except Exception:
                await websocket.send_json({
                    "type": "auth_error",
                    "message": "Помилка обробки запиту"
                })
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

                """
                receive {
                    "type": "password_change",
                    "new_password": "base64(encrypted-aeskey-password)"
                }
                """
                change_data = await asyncio.wait_for(websocket.receive_json(), timeout=300)

                if not isinstance(change_data, dict):
                    await websocket.send_json({
                        "type": "password_change_error",
                        "message": "Невірний формат запиту"
                    })
                    continue

                if frozenset(("type", "new_password")) != change_data.keys():
                    await websocket.send_json({
                        "type": "password_change_error",
                        "message": "Невірний формат зміни пароля"
                    })
                    continue

                if change_data["type"] != "password_change":
                    await websocket.send_json({
                        "type": "password_change_error",
                        "message": "Очікується тип password_change"
                    })
                    continue

                try:
                    new_raw_password = decrypt_text(
                        packet=base64.b64decode(change_data["new_password"]),
                        key=server_aes_key,
                        client_id=client_id,
                    )

                    await database.execute(
                        update(User)
                        .where(
                            User.login == ws_user.login
                        )
                        .values(
                            hashed_password=hash_password(new_raw_password),
                            require_password_change=False
                        )
                    )
                    await database.commit()
                    password_changed = True

                except Exception:
                    await websocket.send_json({
                        "type": "password_change_error",
                        "message": "Помилка зміни пароля"
                    })
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

        ws_connections[client_id] = {"ws": websocket, "aes_key": server_aes_key}
        registered = True

        await websocket.send_json(
            {
                "type": "auth_success",
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

            if data.get("type") != "encrypted_message":
                raise ValueError("Invalid message type")

            if not isinstance(data.get("data"), str):
                raise ValueError("Invalid message data")

            packet = base64.b64decode(data["data"])
            message = decrypt_text(server_aes_key, packet, client_id)

            await broadcast_encrypted(
                message=message,
                message_type="encrypted_message",
                exclude_client_id=client_id,
            )

    except WebSocketDisconnect:
        pass

    except Exception:
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
