import os, hashlib
import time
import random
import asyncio
import logging
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logger = logging.getLogger(__name__)

_HELLO_PAD_MIN = 32
_HELLO_PAD_MAX = 200
HELLO_SIZE = 256

# SERVER-SIDE CODE

def _hello_pad_len(seed: bytes) -> int:
    h = hashlib.sha256(seed + b'\xff\xfe\xfd').digest()
    span = _HELLO_PAD_MAX - _HELLO_PAD_MIN + 1
    return _HELLO_PAD_MIN + int.from_bytes(h[:2], 'big') % span

class SessionRegistry:
    """Registry for temporary storage and resumption of sessions"""

    def __init__(self, ttl: float = 43200.0):
        self._sessions: dict[bytes, tuple[bytes, float]] = {}
        self._lock = asyncio.Lock()
        self._ttl = ttl

    async def register(self, session_id: bytes, key: bytes) -> None:
        async with self._lock:
            self._sessions[session_id] = (key, time.monotonic() + self._ttl)

    async def get_and_validate(self, session_id: bytes) -> bytes | None:
        async with self._lock:
            entry = self._sessions.get(session_id)
            if not entry:
                return None
            key, expires_at = entry
            if time.monotonic() > expires_at:
                del self._sessions[session_id]
                return None
            return key

    async def cleanup_loop(self, interval: float = 300.0):
        """Periodic background cleanup of stale sessions (every 5 minutes)"""
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            async with self._lock:
                expired = [sid for sid, (_, exp) in self._sessions.items() if now > exp]
                for sid in expired:
                    del self._sessions[sid]
            if expired:
                logger.info(f"Cleaned up {len(expired)} outdated sessions")


class SecureSession:
    """Managing the cryptographic state of a specific connection"""

    MODE_NEW_SESSION = b'\x01'
    MODE_RESUME = b'\x02'

    def __init__(self, key: bytes | None = None):
        self._key = key

    @property
    def key(self) -> bytes | None:
        return self._key

    def _hello_pad_len(self, seed: bytes) -> int:
        h = hashlib.sha256(seed + b'\xff\xfe\xfd').digest()
        span = _HELLO_PAD_MAX - _HELLO_PAD_MIN + 1
        return _HELLO_PAD_MIN + int.from_bytes(h[:2], 'big') % span

    async def negotiate_session(self, reader, writer, registry):
        try:
            hello = await reader.readexactly(HELLO_SIZE)
        except Exception as e:
            logger.warning(f"Failed to read hello packet: {e}")
            return False

        session_id_candidate = hello[:16]
        key = await registry.get_and_validate(session_id_candidate)

        if key:
            nonce = hello[16:28]
            ct_proof = hello[28:60]
            return await self._handle_resume_session(session_id_candidate, key, nonce, ct_proof, writer)
        else:
            client_pub_bytes = hello[:32]
            return await self._handle_new_session(client_pub_bytes, writer, registry)

    async def _handle_new_session(self, client_pub_bytes, writer, registry):
        try:
            client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)
            priv = X25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            writer.write(pub_bytes)
            await writer.drain()

            shared = priv.exchange(client_pub)
            self._key = self._derive_key(shared)

            session_id = os.urandom(16)
            await registry.register(session_id, self._key)
            writer.write(self.encrypt_frame(session_id))
            await writer.drain()
            logger.info(f"New session: {session_id.hex()[:8]}...")
            return True
        except Exception as e:
            logger.error(f"New session error: {e}")
            return False

    async def _handle_resume_session(self, session_id, key, nonce, ct_proof, writer):
        try:
            decrypted = ChaCha20Poly1305(key).decrypt(nonce, ct_proof, None)
            if decrypted != session_id:
                raise ValueError("Proof mismatch")
        except Exception as e:
            logger.warning(f"Resume rejected ({session_id.hex()[:8]}...): {e}")
            writer.close()
            return False

        self._key = key
        writer.write(os.urandom(32) + self.encrypt_frame(b'\x00'))
        await writer.drain()
        logger.info(f"Session resumed: {session_id.hex()[:8]}...")
        return True

    def _derive_key(self, shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'socks-obfs-session-key',
        ).derive(shared_secret)

    def encrypt_frame(self, data: bytes) -> bytes:
        if not self._key:
            raise RuntimeError("The session key has not been initialized")
        nonce = os.urandom(12)
        pad_len = random.randint(0, 1200)
        payload = len(data).to_bytes(2, 'big') + data + os.urandom(pad_len)
        ct = ChaCha20Poly1305(self._key).encrypt(nonce, payload, None)
        return nonce + len(ct).to_bytes(2, 'big') + ct

    async def decrypt_frame(self, reader: asyncio.StreamReader) -> bytes:
        if not self._key:
            raise RuntimeError("The session key has not been initialized")
        nonce = await reader.readexactly(12)
        ct_len = int.from_bytes(await reader.readexactly(2), 'big')
        ct = await reader.readexactly(ct_len)

        payload = ChaCha20Poly1305(self._key).decrypt(nonce, ct, None)
        real_data_len = int.from_bytes(payload[:2], 'big')
        return payload[2: 2 + real_data_len]