"""
Servidor de mensajería segura — relay cifrado + registro de llaves públicas.

El servidor actúa SOLO como intermediario: almacena llaves públicas y
reenvía mensajes cifrados. Nunca puede leer el contenido de los mensajes.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import logging
import os
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secure Messaging Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Almacenamiento en memoria ────────────────────────────────────────────────
# En producción: base de datos con TLS + auditoría de accesos
public_key_registry: dict[str, str] = {}        # username → PEM string
active_connections: dict[str, WebSocket] = {}    # username → websocket activo
message_log: list[dict] = []                     # registro de metadata (sin contenido)


# ── Modelos Pydantic ─────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str
    public_key: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) < 3 or len(v) > 32:
            raise ValueError("El username debe tener entre 3 y 32 caracteres")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("El username solo puede contener letras, números, _ y -")
        return v.lower()

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        """Verifica que sea una llave pública ECC válida antes de almacenarla."""
        try:
            serialization.load_pem_public_key(v.encode(), backend=default_backend())
        except Exception:
            raise ValueError("La llave pública no es un PEM válido")
        return v


# ── Endpoints HTTP ───────────────────────────────────────────────────────────

@app.post("/register")
async def register_user(req: RegisterRequest):
    """
    Registra o actualiza la llave pública de un usuario (upsert).

    Permite re-registro para que si un cliente regenera llaves (nueva sesión,
    contraseña olvidada, etc.) el servidor quede sincronizado con la llave vigente.
    En producción esto requeriría prueba de posesión de la llave privada (challenge-response).
    """
    is_update = req.username in public_key_registry
    public_key_registry[req.username] = req.public_key

    if is_update:
        logger.info(f"Llave pública actualizada: {req.username}")
        return {"status": "updated", "username": req.username}

    logger.info(f"Usuario registrado: {req.username}")
    return {"status": "ok", "username": req.username}


@app.get("/keys/{username}")
async def get_public_key(username: str):
    """
    Retorna la llave pública de un usuario.
    Este endpoint es público — cualquier cliente puede obtener la llave
    pública de cualquier usuario para cifrarle mensajes.
    """
    username = username.lower().strip()
    if username not in public_key_registry:
        raise HTTPException(status_code=404, detail=f"Usuario '{username}' no encontrado")

    return {
        "username": username,
        "public_key": public_key_registry[username]
    }


@app.get("/users")
async def list_users():
    """Lista los usuarios registrados y su estado de conexión."""
    return {
        "users": [
            {
                "username": u,
                "online": u in active_connections
            }
            for u in public_key_registry
        ]
    }


@app.get("/health")
async def health_check():
    return {
        "status": "running",
        "registered_users": len(public_key_registry),
        "online_users": len(active_connections)
    }


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """
    Canal WebSocket por usuario.

    Protocolo de mensajes (JSON):
    - Enviar:   { "to": "bob",    "encrypted_payload": {...} }
    - Recibir:  { "from": "alice","encrypted_payload": {...} }
    - Error:    { "error": "..." }
    - Sistema:  { "system": "...", "users": [...] }
    """
    username = username.lower().strip()

    if username not in public_key_registry:
        await websocket.close(code=4001, reason="Usuario no registrado")
        return

    await websocket.accept()
    active_connections[username] = websocket
    logger.info(f"Conectado: {username} (total online: {len(active_connections)})")

    # Notificar a todos los usuarios que alguien se conectó
    await _broadcast_user_list()

    try:
        while True:
            raw = await websocket.receive_text()

            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"error": "Formato JSON inválido"}))
                continue

            recipient = message.get("to", "").lower().strip()
            encrypted_payload = message.get("encrypted_payload")

            # Validaciones básicas
            if not recipient:
                await websocket.send_text(json.dumps({"error": "Campo 'to' requerido"}))
                continue

            if not encrypted_payload:
                await websocket.send_text(json.dumps({"error": "Campo 'encrypted_payload' requerido"}))
                continue

            if recipient not in public_key_registry:
                await websocket.send_text(json.dumps({
                    "error": f"Usuario '{recipient}' no existe"
                }))
                continue

            if recipient not in active_connections:
                await websocket.send_text(json.dumps({
                    "error": f"Usuario '{recipient}' no está conectado en este momento"
                }))
                continue

            # Registrar metadata (NUNCA el contenido del mensaje)
            message_log.append({
                "from": username,
                "to": recipient,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            # RELAY: reenviar ciphertext sin inspeccionar
            await active_connections[recipient].send_text(json.dumps({
                "from": username,
                "encrypted_payload": encrypted_payload,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))

            logger.info(f"Mensaje relayado: {username} → {recipient}")

    except WebSocketDisconnect:
        if username in active_connections:
            del active_connections[username]
        logger.info(f"Desconectado: {username}")
        await _broadcast_user_list()

    except Exception as e:
        logger.error(f"Error en WebSocket ({username}): {e}")
        if username in active_connections:
            del active_connections[username]


async def _broadcast_user_list():
    """Notifica a todos los clientes conectados la lista actualizada de usuarios."""
    user_list = [
        {"username": u, "online": u in active_connections}
        for u in public_key_registry
    ]
    payload = json.dumps({"system": "user_list_update", "users": user_list})

    disconnected = []
    for uname, ws in active_connections.items():
        try:
            await ws.send_text(payload)
        except Exception:
            disconnected.append(uname)

    for uname in disconnected:
        active_connections.pop(uname, None)


# ── UI Web estática ──────────────────────────────────────────────────────────
# Sirve el frontend si existe el directorio static/
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(os.path.join(static_dir, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
