"""
Generación y gestión de llaves ECC (secp384r1 / NIST P-384).

Decisiones de seguridad:
- Curva P-384: 192 bits de seguridad, recomendada por NIST para datos clasificados.
- Las llaves privadas se cifran con AES-256-CBC + PBKDF2 antes de guardarse.
- BestAvailableEncryption usa el esquema más robusto disponible en OpenSSL.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import hashlib
import os


KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")


def _user_keys_path(username: str) -> str:
    return os.path.join(KEYS_DIR, username)


def generate_key_pair(username: str, password: bytes) -> tuple[bytes, bytes]:
    """
    Genera par de llaves ECC y los persiste en disco.

    Returns:
        (private_pem_encrypted, public_pem)
    """
    private_key = ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )

    # Llave privada cifrada — sin contraseña correcta el archivo es inútil
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    keys_path = _user_keys_path(username)
    os.makedirs(keys_path, exist_ok=True)

    priv_file = os.path.join(keys_path, "private.pem")
    pub_file = os.path.join(keys_path, "public.pem")

    # Permisos restrictivos en la llave privada (solo propietario puede leer)
    with open(priv_file, "wb") as f:
        f.write(private_pem)
    os.chmod(priv_file, 0o600)

    with open(pub_file, "wb") as f:
        f.write(public_pem)

    return private_pem, public_pem


def load_private_key(username: str, password: bytes):
    """
    Carga y descifra la llave privada del usuario.
    Lanza ValueError si la contraseña es incorrecta.
    """
    priv_file = os.path.join(_user_keys_path(username), "private.pem")

    if not os.path.exists(priv_file):
        raise FileNotFoundError(f"No se encontraron llaves para '{username}'. Regístrate primero.")

    with open(priv_file, "rb") as f:
        pem_data = f.read()

    try:
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )
    except (ValueError, TypeError):
        raise ValueError("Contraseña incorrecta o llave privada corrupta.")


def load_public_key(username: str):
    """Carga la llave pública local del usuario."""
    pub_file = os.path.join(_user_keys_path(username), "public.pem")

    if not os.path.exists(pub_file):
        raise FileNotFoundError(f"No se encontró llave pública para '{username}'.")

    with open(pub_file, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def load_public_key_from_pem(pem_string: str):
    """Carga una llave pública desde un string PEM (recibido del servidor)."""
    return serialization.load_pem_public_key(
        pem_string.encode(),
        backend=default_backend()
    )


def get_key_fingerprint(public_key) -> str:
    """
    Genera un fingerprint SHA-256 legible de la llave pública.
    Útil para verificación out-of-band (previene MitM en registro de llaves).
    Formato: ABCD:EFGH:IJKL:MNOP
    """
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(pub_bytes).hexdigest().upper()
    return ":".join(digest[i:i+4] for i in range(0, 32, 4))


def keys_exist(username: str) -> bool:
    """Verifica si el usuario ya tiene llaves generadas."""
    return os.path.exists(os.path.join(_user_keys_path(username), "private.pem"))
