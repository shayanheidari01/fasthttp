import ssl
import threading
from queue import LifoQueue, Empty, Full
from typing import Dict, Tuple, Optional

from .connection import Connection
from .timeouts import Timeout


class ConnectionPool:
    """
    Simple thread-safe connection pool keyed by (scheme, host, port).
    """

    def __init__(self, max_per_host: int = 10) -> None:
        self.max_per_host = max_per_host
        self._pools: Dict[Tuple[str, str, int], LifoQueue] = {}
        self._lock = threading.Lock()

    def _get_queue(self, key: Tuple[str, str, int]) -> LifoQueue:
        with self._lock:
            if key not in self._pools:
                self._pools[key] = LifoQueue(self.max_per_host)
            return self._pools[key]

    def acquire(
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
        try:
            conn = queue.get_nowait()
        except Empty:
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
        return conn

    def release(self, connection: Connection) -> None:
        if connection.closed:
            return
        scheme = connection.scheme or ("https" if connection.use_ssl else "http")
        key = (scheme, connection.addr[0], connection.addr[1])
        queue = self._get_queue(key)
        try:
            queue.put_nowait(connection)
        except Full:
            connection.close()

    def close(self) -> None:
        with self._lock:
            pools = list(self._pools.values())
            self._pools.clear()
        for q in pools:
            while True:
                try:
                    conn = q.get_nowait()
                except Empty:
                    break
                conn.close()
