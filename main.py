import uuid
# import base64

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.templating import Jinja2Templates

# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# from fastapi.staticfiles import StaticFiles

app = FastAPI()
templates = Jinja2Templates(directory="templates")
# app.mount("/static", StaticFiles(directory="static"), name="static")


ws_connections: dict[str, WebSocket] = {}


async def broadcast(message: str):
    for connection in ws_connections.values():
        await connection.send_text(message)


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
    ws_connections[client_id] = websocket

    try:
        while True:
            data = await websocket.receive_text()
            await broadcast(f"Кабан #{client_id} сказав: {data}")
    except WebSocketDisconnect:
        del ws_connections[client_id]
        await broadcast(f"Кабан #{client_id} с'їбався з чату")
