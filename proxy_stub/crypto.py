import os
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

    async def negotiate_session(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            registry: SessionRegistry
    ) -> bool:
        """
        Performs either a full ECDH handshake or verifies session resumption.
        Returns True if the key is successfully set, otherwise False
        """
        try:
            mode = await reader.readexactly(1)
        except Exception as e:
            logger.warning(f"Couldn't read session mode: {e}")
            return False

        if mode == self.MODE_NEW_SESSION:
            return await self._handle_new_session(reader, writer, registry)
        elif mode == self.MODE_RESUME:
            return await self._handle_resume_session(reader, writer, registry)
        else:
            logger.warning(f"Unknown connection mode has been received: {mode.hex()}")
            return False

    async def _handle_new_session(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            registry: SessionRegistry
    ) -> bool:
        try:
            client_pub_bytes = await reader.readexactly(32)
            client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)

            priv = X25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            writer.write(pub_bytes)
            await writer.drain()

            shared = priv.exchange(client_pub)
            self._key = self._derive_key(shared)

            session_id = os.urandom(16)
            await registry.register(session_id, self._key)

            # Sending the encrypted session_id to the client
            writer.write(self.encrypt_frame(session_id))
            await writer.drain()
            logger.info(f"A new session has been started: {session_id.hex()[:8]}...")
            return True
        except Exception as e:
            logger.error(f"Ошибка при установлении новой сессии (ECDH): {e}")
            return False

    async def _handle_resume_session(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            registry: SessionRegistry
    ) -> bool:
        try:
            session_id = await reader.readexactly(16)
            nonce = await reader.readexactly(12)
            proof = await reader.readexactly(32)  # encrypt(key, nonce, sid) = 16 data + 16 tag
        except Exception as e:
            logger.warning(f"Error reading the resume parameters: {e}")
            return False

        key = await registry.get_and_validate(session_id)
        if not key:
            logger.warning(f"Resumption rejected: session {session_id.hex()[:8]}... not found or expired")
            writer.write(b'\x01')
            await writer.drain()
            return False

        try:
            decrypted = ChaCha20Poly1305(key).decrypt(nonce, proof, None)
            if decrypted != session_id:
                raise ValueError("Invalid confirmation token (proof)")
        except Exception as e:
            logger.warning(f"Couldn't resume session {session_id.hex()[:8]}... : {e}")
            writer.write(b'\x01')
            await writer.drain()
            return False

        self._key = key
        writer.write(b'\x00')
        await writer.drain()
        logger.info(f"Session resumed successfully: {session_id.hex()[:8]}...")
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