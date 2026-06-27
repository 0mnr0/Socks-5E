import socket
import asyncio
import logging
from typing import Optional, Tuple
from crypto import SecureSession

logger = logging.getLogger(__name__)


class Socks5ServerNegotiator:
    """Processing an encrypted SOCKS5 dialog with an incoming client"""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session: SecureSession):
        self.reader = reader
        self.writer = writer
        self.session = session

    def _send_encrypted(self, data: bytes) -> None:
        self.writer.write(self.session.encrypt_frame(data))

    async def negotiate(self, proxy_user: str, proxy_pass: str) -> Optional[Tuple[str, int]]:
        """
        Performs parsing of SOCKS5 greetings, authorization, and the CONNECT command.
        Returns a tuple (host, port) upon successful negotiation, otherwise None
        """
        try:
            greeting = await self.session.decrypt_frame(self.reader)
        except Exception as e:
            logger.warning(f"Error when receiving SOCKS5 greeting: {e}")
            return None

        if greeting[0] != 0x05:
            logger.warning("Incorrect version of SOCKS")
            return None

        nmethods = greeting[1]
        methods = set(greeting[2: 2 + nmethods])

        # Authorization processing
        if proxy_user and 0x02 in methods:
            self._send_encrypted(b'\x05\x02')
            await self.writer.drain()

            try:
                auth = await self.session.decrypt_frame(self.reader)
            except Exception as e:
                logger.warning(f"Error when reading authorization data: {e}")
                return None

            ulen = auth[1]
            user = auth[2: 2 + ulen]
            plen = auth[2 + ulen]
            pwd = auth[3 + ulen: 3 + ulen + plen]

            ok = (user == proxy_user.encode() and pwd == proxy_pass.encode())
            self._send_encrypted(bytes([0x01, 0x00 if ok else 0x01]))
            await self.writer.drain()

            if not ok:
                logger.warning("Incorrect SOCKS5 credentials were transmitted")
                return None

        elif 0x00 in methods:
            self._send_encrypted(b'\x05\x00')
            await self.writer.drain()
        else:
            self._send_encrypted(b'\x05\xFF')
            await self.writer.drain()
            logger.warning("There is no suitable authorization method.")
            return None

        # Processing the CONNECT request
        try:
            req = await self.session.decrypt_frame(self.reader)
        except Exception as e:
            logger.warning(f"Error when receiving the CONNECT request: {e}")
            return None

        if len(req) < 4 or req[0] != 0x05:
            return None

        cmd, atyp = req[1], req[3]
        if cmd != 0x01:
            self._send_encrypted(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await self.writer.drain()
            return None

        try:
            if atyp == 0x01:
                host = socket.inet_ntoa(req[4:8])
                port = int.from_bytes(req[8:10], 'big')
            elif atyp == 0x03:
                dlen = req[4]
                host = req[5: 5 + dlen].decode()
                port = int.from_bytes(req[5 + dlen: 7 + dlen], 'big')
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, req[4:20])
                port = int.from_bytes(req[20:22], 'big')
            else:
                self._send_encrypted(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                await self.writer.drain()
                return None
        except Exception as e:
            logger.error(f"Target address parsing error: {e}")
            return None

        return host, port