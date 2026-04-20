"""
Tests de la capa criptográfica.

Ejecutar: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from keygen import generate_key_pair, load_private_key, load_public_key, get_key_fingerprint
from crypto import encrypt_message, decrypt_message


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def alice_keys():
    """Genera par de llaves para Alice (reutilizado en todos los tests del módulo)."""
    private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private, private.public_key()

@pytest.fixture(scope="module")
def bob_keys():
    private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    return private, private.public_key()


# ── Tests de cifrado/descifrado ──────────────────────────────────────────────

class TestEncryptDecrypt:

    def test_basic_roundtrip(self, alice_keys, bob_keys):
        """El mensaje descifrado debe ser idéntico al original."""
        bob_priv, bob_pub = bob_keys
        plaintext = "Hola Bob, esto es un mensaje secreto."

        payload = encrypt_message(plaintext, bob_pub, sender_username="alice")
        result, sender = decrypt_message(payload, bob_priv)

        assert result == plaintext
        assert sender == "alice"

    def test_wrong_private_key_fails(self, alice_keys, bob_keys):
        """Descifrar con la llave equivocada debe fallar (integridad AES-GCM)."""
        _, bob_pub = bob_keys
        alice_priv, _ = alice_keys

        payload = encrypt_message("Secreto", bob_pub, sender_username="alice")

        with pytest.raises(ValueError, match="integridad"):
            decrypt_message(payload, alice_priv)

    def test_tampered_ciphertext_rejected(self, bob_keys):
        """Modificar el ciphertext debe invalidar el tag de autenticación GCM."""
        import base64
        bob_priv, bob_pub = bob_keys

        payload = encrypt_message("Mensaje importante", bob_pub)

        # Corromper el ciphertext (cambiar último byte)
        ct_bytes = bytearray(base64.b64decode(payload["ciphertext"]))
        ct_bytes[-1] ^= 0xFF   # flip bits del último byte
        payload["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode()

        with pytest.raises(ValueError, match="integridad"):
            decrypt_message(payload, bob_priv)

    def test_tampered_nonce_rejected(self, bob_keys):
        """Modificar el nonce debe hacer que el tag falle."""
        import base64
        bob_priv, bob_pub = bob_keys

        payload = encrypt_message("Otro mensaje", bob_pub)

        nonce = bytearray(base64.b64decode(payload["nonce"]))
        nonce[0] ^= 0x01
        payload["nonce"] = base64.b64encode(bytes(nonce)).decode()

        with pytest.raises(ValueError):
            decrypt_message(payload, bob_priv)

    def test_empty_message(self, bob_keys):
        """Debe poder cifrar y descifrar mensajes vacíos."""
        bob_priv, bob_pub = bob_keys
        payload = encrypt_message("", bob_pub)
        result, _ = decrypt_message(payload, bob_priv)
        assert result == ""

    def test_unicode_message(self, bob_keys):
        """Debe manejar correctamente caracteres Unicode."""
        bob_priv, bob_pub = bob_keys
        text = "¡Hóla! 🔐 Mensajería segura こんにちは"

        payload = encrypt_message(text, bob_pub)
        result, _ = decrypt_message(payload, bob_priv)

        assert result == text

    def test_each_message_has_unique_nonce(self, bob_keys):
        """Dos cifrados del mismo mensaje deben producir nonces distintos."""
        import base64
        _, bob_pub = bob_keys

        p1 = encrypt_message("Mismo texto", bob_pub)
        p2 = encrypt_message("Mismo texto", bob_pub)

        assert p1["nonce"] != p2["nonce"]

    def test_each_message_has_unique_ephemeral_key(self, bob_keys):
        """Cada mensaje debe usar una llave efímera distinta (PFS)."""
        _, bob_pub = bob_keys

        p1 = encrypt_message("Texto", bob_pub)
        p2 = encrypt_message("Texto", bob_pub)

        assert p1["ephemeral_public_key"] != p2["ephemeral_public_key"]

    def test_aad_mismatch_rejected(self, bob_keys):
        """Cambiar el AAD debe invalidar el mensaje."""
        import base64
        bob_priv, bob_pub = bob_keys

        payload = encrypt_message("Mensaje", bob_pub, sender_username="alice")

        # Reemplazar AAD — simula un ataque de reasignación de mensajes
        payload["aad"] = base64.b64encode(b"mallory").decode()

        with pytest.raises(ValueError):
            decrypt_message(payload, bob_priv)

    def test_large_message(self, bob_keys):
        """Debe manejar mensajes de varios KB."""
        bob_priv, bob_pub = bob_keys
        large_text = "A" * 10_000

        payload = encrypt_message(large_text, bob_pub)
        result, _ = decrypt_message(payload, bob_priv)

        assert result == large_text


# ── Tests de llaves ──────────────────────────────────────────────────────────

class TestKeygenFingerprint:

    def test_fingerprint_format(self, alice_keys):
        """El fingerprint debe tener el formato XXXX:XXXX:..."""
        _, alice_pub = alice_keys
        fp = get_key_fingerprint(alice_pub)

        parts = fp.split(":")
        assert len(parts) == 8
        assert all(len(p) == 4 for p in parts)
        assert fp == fp.upper()

    def test_fingerprint_deterministic(self, alice_keys):
        """El mismo par de llaves siempre produce el mismo fingerprint."""
        _, alice_pub = alice_keys
        fp1 = get_key_fingerprint(alice_pub)
        fp2 = get_key_fingerprint(alice_pub)
        assert fp1 == fp2

    def test_different_keys_different_fingerprints(self, alice_keys, bob_keys):
        """Llaves distintas deben producir fingerprints distintos."""
        _, alice_pub = alice_keys
        _, bob_pub   = bob_keys
        assert get_key_fingerprint(alice_pub) != get_key_fingerprint(bob_pub)
