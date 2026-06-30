import os
import asyncio
import logging
from typing import Optional

from crypto_server import SessionRegistry, SecureSession
from socks import Socks5ServerNegotiator

LogLevel = int(os.getenv('logLevel',   '30'))
logging.basicConfig(level=LogLevel, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

LISTEN_IP   = os.getenv('LISTEN_IP',   '0.0.0.0')
LISTEN_PORT = int(os.getenv('LISTEN_PORT', 48980))
PROXY_USER  = "abc"
PROXY_PASS  = "CDE"
SESSION_TTL = (1 * 3600)/6

# THATS A SERVER SIDE

if len(PROXY_USER) == 0 or len(PROXY_PASS) == 0:
    PROXY_USER, PROXY_PASS = None, None
    logger.warning("You are running proxy without any password or username! To fix this warning - generate auth via run ./genAuth.sh ")


class SocksObfsServer:
    def __init__(self, listen_ip: str, listen_port: int, proxy_user: str, proxy_pass: str):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        self.registry = SessionRegistry(ttl=SESSION_TTL)
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        """Start Server and background cleanup service"""
        asyncio.create_task(self.registry.cleanup_loop())

        self.server = await asyncio.start_server(self._handle_client, self.listen_ip, self.listen_port)
        logger.warning(f"Relay started on {self.listen_ip}:{self.listen_port}")
        if self.proxy_user:
            logger.info(f"Авторизация SOCKS5 включена (user: {self.proxy_user})")
        else:
            logger.info("SOCKS5 authorization is disabled")

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        peer = client_writer.get_extra_info('peername')
        target_writer = None
        logger.info(f"New connection from {peer}")

        try:
            # [1] Handshake or session resuming
            session = SecureSession()
            success = await asyncio.wait_for(
                session.negotiate_session(client_reader, client_writer, self.registry),
                timeout=10
            )
            if not success:
                self._close_writers(client_writer)
                return
            logger.info(f"[{peer}] Tunnel authorization is successful")

            # [2] Local SOCKS negotiation
            negotiator = Socks5ServerNegotiator(client_reader, client_writer, session)
            result = await asyncio.wait_for(
                negotiator.negotiate(self.proxy_user, self.proxy_pass),
                timeout=15
            )
            if result is None:
                self._close_writers(client_writer)
                return
            host, port = result
            logger.info(f"[{peer}] The CONNECT to request {host}:{port}")

            # [3] Connecting to the destination host
            try:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=10
                )
            except Exception as e:
                logger.error(f"[{peer}] Connection error to {host}:{port}: {e}")
                client_writer.write(session.encrypt_frame(
                    b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00'
                ))
                await client_writer.drain()
                self._close_writers(client_writer)
                return

            # Sending a successful CONNECT response to the client
            client_writer.write(session.encrypt_frame(
                b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            ))
            await client_writer.drain()
            logger.info(f"[{peer}] A connection has been established with {host}:{port}")

            # [4] Bidirectional data transmission
            async with asyncio.TaskGroup() as tg:
                tg.create_task(self._pipe_client_to_target(client_reader, target_writer, session))
                tg.create_task(self._pipe_target_to_client(target_reader, client_writer, session))

        except* asyncio.TimeoutError:
            logger.warning(f"[{peer}] Connection is closed due to timeout")
        except* Exception as eg:
            for e in eg.exceptions:
                logger.error(f"[{peer}] Error in asynchronous flow: {type(e).__name__}: {e}")
        finally:
            logger.info(f"[{peer}] Connection completed")
            self._close_writers(client_writer, target_writer)

    async def _pipe_client_to_target(self, client_reader: asyncio.StreamReader, target_writer: asyncio.StreamWriter, session: SecureSession):
        try:
            while True:
                data = await session.decrypt_frame(client_reader)
                target_writer.write(data)
                await target_writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.debug(f"Exception pipe_client_to_target: {type(e).__name__}: {e}")
        finally:
            self._close_writers(target_writer)

    async def _pipe_target_to_client(self, target_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, session: SecureSession):
        try:
            while True:
                data = await target_reader.read(4096)
                if not data:
                    break
                client_writer.write(session.encrypt_frame(data))
                await client_writer.drain()
        except Exception as e:
            logger.debug(f"Exception pipe_target_to_client: {type(e).__name__}: {e}")
        finally:
            self._close_writers(client_writer)

    @staticmethod
    def _close_writers(*writers: Optional[asyncio.StreamWriter]):
        for w in writers:
            if w:
                try:
                    if not w.is_closing():
                        w.close()
                except Exception:
                    pass


async def main():
    server = SocksObfsServer(
        listen_ip=LISTEN_IP,
        listen_port=LISTEN_PORT,
        proxy_user=PROXY_USER,
        proxy_pass=PROXY_PASS
    )
    await server.start()


if __name__ == '__main__':
    try:
        print("Starting server...")
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")