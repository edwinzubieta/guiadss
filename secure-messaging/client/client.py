"""
Cliente de mensajería segura — interfaz de consola.

Uso:
    python client.py <username>

Comandos en sesión:
    /msg <destinatario> <mensaje>   Enviar mensaje cifrado
    /users                          Listar usuarios conectados
    /fp                             Mostrar fingerprint de tu llave pública
    /help                           Mostrar ayuda
    /exit                           Salir
"""

import asyncio
import websockets
import httpx
import json
import getpass
import sys
import os
from datetime import datetime

# Ajustar path para importar módulos del mismo directorio
sys.path.insert(0, os.path.dirname(__file__))

from keygen import (
    generate_key_pair,
    load_private_key,
    load_public_key,
    load_public_key_from_pem,
    get_key_fingerprint,
    keys_exist,
)
from crypto import encrypt_message, decrypt_message

SERVER_HTTP = "http://localhost:8000"
SERVER_WS   = "ws://localhost:8000"

# ── Colores ANSI para la consola ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def print_info(msg: str):
    print(f"{C.DIM}[{_ts()}]{C.RESET} {C.CYAN}[INFO]{C.RESET} {msg}")

def print_success(msg: str):
    print(f"{C.DIM}[{_ts()}]{C.RESET} {C.GREEN}[OK]{C.RESET}   {msg}")

def print_error(msg: str):
    print(f"{C.DIM}[{_ts()}]{C.RESET} {C.RED}[ERR]{C.RESET}  {msg}")

def print_msg_in(sender: str, text: str):
    print(f"\n{C.DIM}[{_ts()}]{C.RESET} {C.MAGENTA}{C.BOLD}{sender}{C.RESET}{C.MAGENTA} →{C.RESET} {text}\n", flush=True)

def print_msg_out(recipient: str, text: str):
    print(f"{C.DIM}[{_ts()}]{C.RESET} {C.GREEN}tú → {recipient}:{C.RESET} {text}")

def print_system(msg: str):
    print(f"{C.DIM}[{_ts()}] [SYS] {msg}{C.RESET}")


# ── Cliente ──────────────────────────────────────────────────────────────────

class SecureMessagingClient:

    def __init__(self, username: str):
        self.username = username.lower().strip()
        self.private_key = None
        self.public_key = None
        self.online_users: list[dict] = []
        self.http = httpx.AsyncClient(base_url=SERVER_HTTP, timeout=10.0)
        self._ws = None
        self._input_queue: asyncio.Queue = asyncio.Queue()

    # ── Setup ────────────────────────────────────────────────────────────────

    async def setup(self) -> bool:
        """Inicializa llaves y registra al usuario en el servidor."""
        print(f"\n{C.BOLD}{'─'*55}")
        print(f"  Mensajería Segura — E2E con ECC/ECIES + AES-256-GCM")
        print(f"{'─'*55}{C.RESET}\n")

        password = getpass.getpass(f"  Contraseña para '{self.username}': ").encode()
        if not password:
            print_error("La contraseña no puede estar vacía.")
            return False

        if keys_exist(self.username):
            print_info("Llaves encontradas. Cargando...")
            try:
                self.private_key = load_private_key(self.username, password)
                self.public_key  = load_public_key(self.username)
                print_success("Llave privada cargada y descifrada correctamente.")
            except ValueError:
                print_error("Contraseña incorrecta.")
                return False
        else:
            print_info("Generando nuevo par de llaves ECC (secp384r1)...")
            generate_key_pair(self.username, password)
            self.private_key = load_private_key(self.username, password)
            self.public_key  = load_public_key(self.username)
            print_success("Par de llaves generado y almacenado (llave privada cifrada).")

        fp = get_key_fingerprint(self.public_key)
        print_info(f"Fingerprint de tu llave pública: {C.YELLOW}{fp}{C.RESET}")
        print_info("Comparte este fingerprint con tus contactos para verificar tu identidad.\n")

        # Registrar en el servidor
        from cryptography.hazmat.primitives import serialization as _s
        pub_pem = self.public_key.public_bytes(
            encoding=_s.Encoding.PEM,
            format=_s.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        try:
            resp = await self.http.post("/register", json={
                "username": self.username,
                "public_key": pub_pem
            })
            if resp.status_code == 201:
                print_success("Llave pública registrada en el servidor.")
            elif resp.status_code == 409:
                print_info("Usuario ya registrado en el servidor.")
            else:
                print_error(f"Error al registrar: {resp.text}")
                return False
        except httpx.ConnectError:
            print_error("No se puede conectar al servidor en localhost:8000")
            print_error("Asegúrate de que el servidor esté corriendo: uvicorn server:app --reload")
            return False

        return True

    # ── Enviar mensaje ───────────────────────────────────────────────────────

    async def send_message(self, recipient: str, message: str):
        """Obtiene la llave pública del destinatario, cifra y envía."""
        recipient = recipient.lower().strip()

        try:
            resp = await self.http.get(f"/keys/{recipient}")
        except httpx.ConnectError:
            print_error("Perdida conexión con el servidor.")
            return

        if resp.status_code == 404:
            print_error(f"El usuario '{recipient}' no está registrado.")
            return
        if resp.status_code != 200:
            print_error(f"Error al obtener llave de '{recipient}': {resp.text}")
            return

        recipient_pub_key = load_public_key_from_pem(resp.json()["public_key"])

        try:
            payload = encrypt_message(message, recipient_pub_key, sender_username=self.username)
        except Exception as e:
            print_error(f"Error al cifrar: {e}")
            return

        try:
            await self._ws.send(json.dumps({
                "to": recipient,
                "encrypted_payload": payload
            }))
            print_msg_out(recipient, message)
        except Exception as e:
            print_error(f"Error al enviar: {e}")

    # ── Recibir mensajes ─────────────────────────────────────────────────────

    async def _receive_loop(self):
        """Escucha mensajes entrantes del servidor en segundo plano."""
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                # Mensaje del sistema (lista de usuarios)
                if "system" in data:
                    if data["system"] == "user_list_update":
                        self.online_users = data.get("users", [])
                    continue

                # Error del servidor
                if "error" in data:
                    print_error(data["error"])
                    continue

                # Mensaje cifrado entrante
                if "from" in data and "encrypted_payload" in data:
                    sender = data["from"]
                    try:
                        plaintext, verified_sender = decrypt_message(
                            data["encrypted_payload"],
                            self.private_key
                        )
                        # Verificar que el AAD coincide con quien dice ser el remitente
                        if verified_sender and verified_sender != sender:
                            print_error(
                                f"ADVERTENCIA: El mensaje dice ser de '{sender}' "
                                f"pero el AAD dice '{verified_sender}'. Posible replay."
                            )
                        else:
                            print_msg_in(sender, plaintext)

                    except ValueError as e:
                        print_error(f"Mensaje de '{sender}' RECHAZADO: {e}")

        except websockets.ConnectionClosed:
            print_system("Conexión con el servidor cerrada.")
        except Exception as e:
            print_error(f"Error en receive loop: {e}")

    # ── Loop de comandos ─────────────────────────────────────────────────────

    async def _command_loop(self):
        """Lee comandos del usuario desde stdin de forma asíncrona."""
        loop = asyncio.get_event_loop()

        self._print_help()

        while True:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                line = line.strip()
                if not line:
                    continue

                parts = line.split(maxsplit=2)
                cmd = parts[0].lower()

                if cmd == "/exit":
                    print_info("Cerrando sesión...")
                    return

                elif cmd == "/help":
                    self._print_help()

                elif cmd == "/fp":
                    fp = get_key_fingerprint(self.public_key)
                    print_info(f"Tu fingerprint: {C.YELLOW}{fp}{C.RESET}")

                elif cmd == "/users":
                    if not self.online_users:
                        print_info("No hay información de usuarios todavía.")
                    else:
                        print_info("Usuarios registrados:")
                        for u in self.online_users:
                            status = f"{C.GREEN}● online{C.RESET}" if u["online"] else f"{C.DIM}○ offline{C.RESET}"
                            marker = " ← tú" if u["username"] == self.username else ""
                            print(f"    {u['username']}{marker}  {status}")

                elif cmd == "/msg":
                    if len(parts) < 3:
                        print_error("Uso: /msg <destinatario> <mensaje>")
                        continue
                    recipient = parts[1]
                    message   = parts[2]
                    await self.send_message(recipient, message)

                else:
                    # Atajo: "destinatario: mensaje" sin comando explícito
                    if ":" in line:
                        recipient, _, message = line.partition(":")
                        await self.send_message(recipient.strip(), message.strip())
                    else:
                        print_error(f"Comando desconocido: '{cmd}'. Escribe /help")

            except (EOFError, KeyboardInterrupt):
                print_info("\nInterrumpido.")
                return

    def _print_help(self):
        print(f"""
{C.BOLD}  Comandos disponibles:{C.RESET}
    {C.CYAN}/msg <usuario> <texto>{C.RESET}   Enviar mensaje cifrado
    {C.CYAN}/users{C.RESET}                   Ver usuarios y estado
    {C.CYAN}/fp{C.RESET}                      Ver fingerprint de tu llave pública
    {C.CYAN}/help{C.RESET}                    Mostrar esta ayuda
    {C.CYAN}/exit{C.RESET}                    Salir
  {C.DIM}Atajo: "usuario: mensaje"{C.RESET}
""")

    # ── Punto de entrada ─────────────────────────────────────────────────────

    async def run(self):
        if not await self.setup():
            return

        ws_url = f"{SERVER_WS}/ws/{self.username}"
        try:
            async with websockets.connect(ws_url) as ws:
                self._ws = ws
                print_success(f"Conectado al servidor como '{C.BOLD}{self.username}{C.RESET}'.\n")

                # Correr recepción y comandos en paralelo
                receive_task = asyncio.create_task(self._receive_loop())
                command_task = asyncio.create_task(self._command_loop())

                # Terminar cuando cualquiera de las dos finalice
                done, pending = await asyncio.wait(
                    [receive_task, command_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()

        except (ConnectionRefusedError, OSError):
            print_error("No se puede conectar al servidor WebSocket en localhost:8000")
        except Exception as e:
            print_error(f"Error de conexión: {e}")
        finally:
            await self.http.aclose()
            print_info("Sesión terminada.")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: python client.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    try:
        asyncio.run(SecureMessagingClient(username).run())
    except KeyboardInterrupt:
        print("\nSaliendo...")
