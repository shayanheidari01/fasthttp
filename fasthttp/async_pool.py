import asyncio
import ssl
from typing import Dict, Tuple, Optional

from .async_connection import AsyncConnection
from .timeouts import Timeout


class AsyncConnectionPool:
    """
    Simple asyncio-based connection pool keyed by (scheme, host, port).
    """

    def __init__(self, max_per_host: int = 50) -> None:
        self.max_per_host = max_per_host
        self._pools: Dict[Tuple[str, str, int], asyncio.LifoQueue] = {}
        self._locks: Dict[Tuple[str, str, int], asyncio.Lock] = {}

    def _get_queue(self, key: Tuple[str, str, int]) -> asyncio.LifoQueue:
        if key not in self._pools:
            self._pools[key] = asyncio.LifoQueue(self.max_per_host)
            self._locks[key] = asyncio.Lock()
        return self._pools[key]

    async def acquire(
        self,
        scheme: str,
        host: str,
        port: int,
        *,
        timeout: Timeout,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> AsyncConnection:
        key = (scheme, host, port)
        queue = self._get_queue(key)
        try:
            conn = queue.get_nowait()
        except asyncio.QueueEmpty:
            use_ssl = scheme == "https"
            conn = AsyncConnection(
                (host, port),
                use_ssl=use_ssl,
                connect_timeout=timeout.connect,
                read_timeout=timeout.read,
                write_timeout=timeout.write,
                verify=verify,
                ssl_context=ssl_context,
                scheme=scheme,
            )
        return conn

    async def release(self, connection: AsyncConnection) -> None:
        if connection.closed:
            return
        scheme = connection.scheme or ("https" if connection.use_ssl else "http")
        key = (scheme, connection.addr[0], connection.addr[1])
        queue = self._get_queue(key)
        try:
            queue.put_nowait(connection)
        except asyncio.QueueFull:
            await connection.close()

    async def close(self) -> None:
        pools = list(self._pools.values())
        self._pools.clear()
        for q in pools:
            while True:
                try:
                    conn = q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                await conn.close()
