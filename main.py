import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.templating import Jinja2Templates

# from fastapi.staticfiles import StaticFiles

app = FastAPI()

# app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)


manager = ConnectionManager()


@app.get("/")
async def index(request: Request):
    client_id = str(uuid.uuid4())
    is_https = request.url.scheme == "https"
    if is_https:
        ws_protocol = "wss"
        host = request.url.hostname
    else:
        ws_protocol = "ws"
        host = request.url.netloc

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "ws_url": f"{ws_protocol}://{host}/ws/{client_id}"
        }
    )


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(f"Кабан #{client_id} сказав: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(f"Кабан #{client_id} с'їбався з чату")
