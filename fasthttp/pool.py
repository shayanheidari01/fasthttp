import asyncio
import ssl
import time
from typing import Dict, Tuple, Optional

from .connection import Connection
from .timeouts import Timeout


class ConnectionPool:
    """
    Async asyncio-based connection pool keyed by (scheme, host, port).
    Includes connection health checks and keep-alive timeout management.
    """

    def __init__(
        self,
        max_per_host: int = 50,
        keepalive_timeout: float = 30.0,
        enable_health_check: bool = True,
    ) -> None:
        self.max_per_host = max_per_host
        self.keepalive_timeout = keepalive_timeout
        self.enable_health_check = enable_health_check
        self._pools: Dict[Tuple[str, str, int], asyncio.LifoQueue] = {}
        self._locks: Dict[Tuple[str, str, int], asyncio.Lock] = {}
        # Track when connections were last used
        self._connection_times: Dict[Connection, float] = {}

    def _get_queue(self, key: Tuple[str, str, int]) -> asyncio.LifoQueue:
        if key not in self._pools:
            self._pools[key] = asyncio.LifoQueue(self.max_per_host)
            self._locks[key] = asyncio.Lock()
        return self._pools[key]

    def _is_connection_healthy(self, conn: Connection) -> bool:
        """Check if connection is healthy and not expired."""
        if conn.closed:
            return False
        
        # Check keep-alive timeout
        if conn in self._connection_times:
            last_used = self._connection_times[conn]
            if time.monotonic() - last_used > self.keepalive_timeout:
                return False
        
        # Check if connection is actually connected
        if not getattr(conn, "_connected", False):
            return False
        
        return True

    async def acquire(
        self,
        scheme: str,
        host: str,
        port: int,
        *,
        timeout: Timeout,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> Connection:
        key = (scheme, host, port)
        queue = self._get_queue(key)
        
        # Try to get a connection from pool
        while True:
            try:
                conn = queue.get_nowait()
                # Check if connection is still healthy
                if self.enable_health_check and not self._is_connection_healthy(conn):
                    # Connection is dead, close it and try next one
                    await conn.close()
                    if conn in self._connection_times:
                        del self._connection_times[conn]
                    continue
                # Connection is healthy, update last used time
                self._connection_times[conn] = time.monotonic()
                return conn
            except asyncio.QueueEmpty:
                break
        
        # No healthy connection available, create new one
        use_ssl = scheme == "https"
        conn = Connection(
            (host, port),
            use_ssl=use_ssl,
            connect_timeout=timeout.connect,
            read_timeout=timeout.read,
            write_timeout=timeout.write,
            verify=verify,
            ssl_context=ssl_context,
            scheme=scheme,
        )
        self._connection_times[conn] = time.monotonic()
        return conn

    async def release(self, connection: Connection) -> None:
        """Release a connection back to the pool."""
        if connection.closed:
            if connection in self._connection_times:
                del self._connection_times[connection]
            return
        
        # Check if connection is still healthy before returning to pool
        if self.enable_health_check and not self._is_connection_healthy(connection):
            await connection.close()
            if connection in self._connection_times:
                del self._connection_times[connection]
            return
        
        scheme = connection.scheme or ("https" if connection.use_ssl else "http")
        key = (scheme, connection.addr[0], connection.addr[1])
        queue = self._get_queue(key)
        
        # Update last used time
        self._connection_times[connection] = time.monotonic()
        
        try:
            queue.put_nowait(connection)
        except asyncio.QueueFull:
            # Pool is full, close the connection
            await connection.close()
            if connection in self._connection_times:
                del self._connection_times[connection]

    async def close(self) -> None:
        """Close all connections in the pool."""
        pools = list(self._pools.values())
        self._pools.clear()
        self._locks.clear()
        
        for q in pools:
            while True:
                try:
                    conn = q.get_nowait()
                    await conn.close()
                    if conn in self._connection_times:
                        del self._connection_times[conn]
                except asyncio.QueueEmpty:
                    break
        
        self._connection_times.clear()

    async def cleanup_expired(self) -> None:
        """Remove expired connections from all pools."""
        if not self.enable_health_check:
            return
        
        current_time = time.monotonic()
        expired_connections = [
            conn for conn, last_used in self._connection_times.items()
            if current_time - last_used > self.keepalive_timeout
        ]
        
        for conn in expired_connections:
            await conn.close()
            if conn in self._connection_times:
                del self._connection_times[conn]
        
        # Remove expired connections from queues
        for queue in self._pools.values():
            temp_connections = []
            while True:
                try:
                    conn = queue.get_nowait()
                    if self._is_connection_healthy(conn):
                        temp_connections.append(conn)
                    else:
                        await conn.close()
                        if conn in self._connection_times:
                            del self._connection_times[conn]
                except asyncio.QueueEmpty:
                    break
            
            # Put healthy connections back
            for conn in temp_connections:
                try:
                    queue.put_nowait(conn)
                except asyncio.QueueFull:
                    await conn.close()
                    if conn in self._connection_times:
                        del self._connection_times[conn]

