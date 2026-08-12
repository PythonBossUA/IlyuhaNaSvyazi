import os
import uuid
import base64
import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, status
from fastapi.templating import Jinja2Templates

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI()
templates = Jinja2Templates(directory="templates")

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

    public_numbers = ec.EllipticCurvePublicNumbers(
        x=x,
        y=y,
        curve=ec.SECP256R1()
    )

    return public_numbers.public_key()


# ============================================================
# Виведення AES-ключа
# ============================================================

def derive_aes_key(
    my_private_key,
    peer_public_key,
    salt: bytes,
    info: bytes
) -> bytes:
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
    source_client_id: str = None
):
    for client_id, connection in list(ws_connections.items()):
        if client_id == exclude_client_id:
            continue

        try:
            encrypted = encrypt_text(connection["aes_key"], message, client_id)

            payload = {
                "type": message_type,
                "data": base64.b64encode(encrypted).decode()
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
# Routes
# ============================================================

@app.get("/")
async def index(request: Request):
    client_id = str(uuid.uuid4())

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "client_id": client_id
        }
    )


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await websocket.accept()

    client_public_json__task = None
    registered = False

    try:
        client_public_json__task = asyncio.create_task(
            websocket.receive_json()
        )

        server_private_key = generate_private_key()
        server_public_jwk = export_public_jwk(server_private_key)

        await websocket.send_json({
            "type": "public_key",
            "jwk": server_public_jwk
        })

        client_public_json = await asyncio.wait_for(
            client_public_json__task, timeout=5
        )

        if not isinstance(client_public_json, dict):
            raise ValueError("Invalid handshake message")

        if client_public_json.get("type") != "public_key":
            raise ValueError("Expected public_key message")

        client_public_jwk = client_public_json.get("jwk")

        if not isinstance(client_public_jwk, dict):
            raise ValueError("Missing JWK")

        client_public_key = import_public_jwk(client_public_jwk)

        salt = client_id.encode()
        info = b"default_messenger"

        server_aes_key = derive_aes_key(
            server_private_key,
            client_public_key,
            salt,
            info
        )

        old_ws = ws_connections.get(client_id)
        if old_ws is not None:
            old_connection = old_ws["ws"]
            if old_connection is not websocket:
                try:
                    await old_connection.close(code=1000)
                except Exception:
                    pass

        ws_connections[client_id] = {
            "ws": websocket,
            "aes_key": server_aes_key
        }
        registered = True

        await websocket.send_json({
            "type": "handshake_ok"
        })

        await broadcast_encrypted(
            message=f"Client {client_id} connected",
            message_type="system_message",
            exclude_client_id=client_id,
            event="connected",
            source_client_id=client_id
        )

        while True:
            data = await websocket.receive_json()

            if not isinstance(data, dict):
                raise ValueError("Invalid message format")

            if data.get("type") != "encrypted_message":
                raise ValueError("Invalid message type")

            if not isinstance(data.get("data"), str):
                raise ValueError("Invalid message data")

            aes_key = ws_connections[client_id]["aes_key"]

            packet = base64.b64decode(data["data"])
            message = decrypt_text(aes_key, packet, client_id)

            await broadcast_encrypted(
                message=message,
                message_type="encrypted_message",
                exclude_client_id=client_id
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
                        source_client_id=client_id
                    )
                except Exception:
                    pass
