"""
Módulo de criptografía — ECIES (Elliptic Curve Integrated Encryption Scheme).

Esquema de cifrado híbrido:
  1. Llave efímera ECC  →  ECDH  →  secreto compartido
  2. HKDF(secreto)      →  llave AES-256
  3. AES-256-GCM        →  cifrado autenticado del mensaje

Por qué cifrado híbrido:
- ECC (y RSA) solo pueden cifrar datos pequeños directamente.
- AES-GCM es eficiente para datos de cualquier tamaño.
- El patrón "ECIES" es el estándar usado en TLS 1.3, Signal, Age, etc.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import base64
import json


# Contexto HKDF — vincula las llaves derivadas a esta aplicación específica.
# Cambiar este valor invalida todos los mensajes anteriores.
_HKDF_INFO = b"secure-messaging-v1-aes256gcm"


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Deriva una llave AES-256 desde el secreto ECDH usando HKDF-SHA384.

    No usar el secreto ECDH directamente como llave AES porque:
    - El punto ECDH puede tener estructura matemática predecible.
    - HKDF aplica una función pseudoaleatoria que elimina sesgos.
    """
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,          # 256 bits → AES-256
        salt=None,          # sin salt → HKDF usa un salt de ceros internamente
        info=_HKDF_INFO,
        backend=default_backend()
    ).derive(shared_secret)


def encrypt_message(plaintext: str, recipient_public_key, sender_username: str = "") -> dict:
    """
    Cifra un mensaje usando ECIES + firma de metadatos.

    Args:
        plaintext: Texto plano a cifrar.
        recipient_public_key: Llave pública ECC del destinatario.
        sender_username: Nombre del remitente (incluido en Additional Data para integridad).

    Returns:
        dict con ephemeral_public_key, nonce, ciphertext (todo en base64).
    """
    # ── Paso 1: Par de llaves efímero ────────────────────────────────────────
    # Una llave nueva por cada mensaje → Perfect Forward Secrecy.
    # Si la llave privada del destinatario se compromete mañana,
    # los mensajes de hoy no pueden descifrarse porque esta llave efímera
    # ya fue descartada de memoria.
    ephemeral_private = ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )
    ephemeral_public = ephemeral_private.public_key()

    # ── Paso 2: ECDH ────────────────────────────────────────────────────────
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

    # ── Paso 3: Derivar llave AES-256 ───────────────────────────────────────
    aes_key = _derive_aes_key(shared_secret)

    # ── Paso 4: AES-256-GCM ─────────────────────────────────────────────────
    # GCM = cifrado CTR + autenticación GHASH.
    # El tag de autenticación (16 bytes) detecta cualquier modificación
    # del ciphertext, del nonce, o del additional_data.
    nonce = os.urandom(12)   # 96 bits — tamaño óptimo para GCM según NIST SP 800-38D

    # Additional Authenticated Data: no se cifra, pero su integridad se verifica.
    # Vincula el mensaje al remitente → evita que el servidor reasigne mensajes.
    aad = sender_username.encode() if sender_username else b""

    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    # Serializar llave pública efímera para enviar al destinatario
    ephemeral_pub_pem = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "ephemeral_public_key": base64.b64encode(ephemeral_pub_pem).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode(),
        "aad": base64.b64encode(aad).decode()
    }


def decrypt_message(encrypted_payload: dict, recipient_private_key) -> tuple[str, str]:
    """
    Descifra un mensaje ECIES y verifica su integridad.

    Returns:
        (plaintext, sender_username_from_aad)

    Raises:
        ValueError: Si el mensaje fue alterado, el nonce reutilizado,
                    o los datos están corruptos.
    """
    try:
        ephemeral_pub_pem = base64.b64decode(encrypted_payload["ephemeral_public_key"])
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ciphertext_with_tag = base64.b64decode(encrypted_payload["ciphertext"])
        aad = base64.b64decode(encrypted_payload.get("aad", ""))
    except (KeyError, Exception):
        raise ValueError("Payload cifrado malformado o campos faltantes.")

    # ── Paso 1: Reconstruir llave pública efímera ────────────────────────────
    try:
        ephemeral_public = serialization.load_pem_public_key(
            ephemeral_pub_pem,
            backend=default_backend()
        )
    except Exception:
        raise ValueError("Llave pública efímera inválida.")

    # ── Paso 2: ECDH con llave privada propia ───────────────────────────────
    # Produce el mismo secreto compartido que el remitente calculó.
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)

    # ── Paso 3: Derivar misma llave AES-256 ─────────────────────────────────
    aes_key = _derive_aes_key(shared_secret)

    # ── Paso 4: Descifrar y verificar integridad ────────────────────────────
    aesgcm = AESGCM(aes_key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        # CRÍTICO: no revelar si el error fue en el tag, nonce, o clave.
        # Los oráculos de padding/tag son vectores de ataque criptográfico.
        raise ValueError("Verificación de integridad fallida — mensaje rechazado.")
    except Exception:
        raise ValueError("Error al descifrar — mensaje corrupto o inválido.")

    sender = aad.decode("utf-8") if aad else "desconocido"
    return plaintext_bytes.decode("utf-8"), sender


def serialize_payload(payload: dict) -> str:
    """Serializa el payload cifrado a JSON string para transmisión."""
    return json.dumps(payload)


def deserialize_payload(payload_str: str) -> dict:
    """Deserializa JSON recibido del servidor."""
    try:
        return json.loads(payload_str)
    except json.JSONDecodeError:
        raise ValueError("Payload no es JSON válido.")
