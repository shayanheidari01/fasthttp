import asyncio
import ssl
import time
from collections import deque
from dataclasses import dataclass
from functools import lru_cache
from typing import Deque, Dict, Optional, Tuple

from .connection import Connection
from .timeouts import Timeout


@dataclass
class _PoolStats:
    """Lightweight container for pool counters to avoid dict churn."""
    total_connections_created: int = 0
    total_connections_reused: int = 0
    total_connections_closed: int = 0
    total_health_checks: int = 0
    total_cache_hits: int = 0
    peak_connections: int = 0

    def snapshot(self, current: int, active_pools: int, health_cache_size: int) -> Dict[str, int]:
        """Return counters plus current derived metrics."""
        return {
            'total_connections_created': self.total_connections_created,
            'total_connections_reused': self.total_connections_reused,
            'total_connections_closed': self.total_connections_closed,
            'total_health_checks': self.total_health_checks,
            'total_cache_hits': self.total_cache_hits,
            'peak_connections': self.peak_connections,
            'current_connections': current,
            'active_pools': active_pools,
            'health_cache_size': health_cache_size,
        }


class ConnectionPool:
    """
    Async asyncio-based connection pool keyed by (scheme, host, port).

    Uses lock-guarded deques instead of asyncio queues to reduce task
    switching overhead and keep CPU usage predictable under heavy load.
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
        self._pools: Dict[Tuple[str, str, int], Deque[Connection]] = {}
        self._locks: Dict[Tuple[str, str, int], asyncio.Lock] = {}
        # Track when connections were last used
        self._connection_times: Dict[Connection, float] = {}
        # Cache for connection health checks to reduce repeated lookups
        self._health_cache: Dict[int, bool] = {}
        # Cache for monotonic time calls to reduce system calls
        self._last_time_check: float = 0.0
        self._cached_time: float = 0.0
        # Statistics for monitoring
        self._stats = _PoolStats()

    @staticmethod
    @lru_cache(maxsize=256)
    def _make_key(scheme: str, host: str, port: int) -> Tuple[str, str, int]:
        """Create and cache connection keys to reduce tuple allocations."""
        return (scheme, host, port)
    
    def _get_current_time(self) -> float:
        """Get current monotonic time with caching to reduce system calls."""
        current = time.monotonic()
        if current - self._last_time_check > 0.001:  # Cache for 1ms
            self._cached_time = current
            self._last_time_check = current
        return self._cached_time
    
    def _get_queue(self, key: Tuple[str, str, int]) -> Deque[Connection]:
        """Get or create deque for a connection key."""
        queue = self._pools.get(key)
        if queue is None:
            queue = deque()
            self._pools[key] = queue
            self._locks[key] = asyncio.Lock()
        return queue

    def _is_connection_healthy(self, conn: Connection) -> bool:
        """Check if connection is healthy and not expired with caching."""
        self._stats.total_health_checks += 1
        
        # Use connection id for caching health status
        conn_id = id(conn)
        
        # Check cache first (cache for 10ms)
        if conn_id in self._health_cache:
            self._stats.total_cache_hits += 1
            return self._health_cache[conn_id]
        
        # Fast path: check if connection is closed first
        if conn.closed:
            self._health_cache[conn_id] = False
            return False
        
        # Check if connection is actually connected
        if not getattr(conn, "_connected", False):
            self._health_cache[conn_id] = False
            return False
        
        # Check keep-alive timeout only if connection is still alive
        if self.enable_health_check and conn in self._connection_times:
            last_used = self._connection_times[conn]
            if self._get_current_time() - last_used > self.keepalive_timeout:
                self._health_cache[conn_id] = False
                return False
        
        # Connection is healthy
        self._health_cache[conn_id] = True
        return True
    
    def _clear_health_cache(self, conn: Connection) -> None:
        """Clear health cache for a specific connection."""
        self._health_cache.pop(id(conn), None)

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
        key = self._make_key(scheme, host, port)
        queue = self._get_queue(key)
        lock = self._locks[key]
        current_time = self._get_current_time()
        
        # Try to get a connection from pool
        stale: list[Connection] = []
        selected: Optional[Connection] = None
        async with lock:
            while queue:
                candidate = queue.pop()
                if self.enable_health_check and not self._is_connection_healthy(candidate):
                    stale.append(candidate)
                    continue
                selected = candidate
                break
        # Close stale connections outside the lock
        for dead in stale:
            await dead.close()
            self._connection_times.pop(dead, None)
            self._clear_health_cache(dead)
            self._stats.total_connections_closed += 1
        
        if selected is not None:
            self._connection_times[selected] = current_time
            self._stats.total_connections_reused += 1
            return selected
        
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
        self._connection_times[conn] = current_time
        self._stats.total_connections_created += 1
        
        # Update peak connections
        current_total = len(self._connection_times)
        if current_total > self._stats.peak_connections:
            self._stats.peak_connections = current_total
        
        return conn

    async def release(self, connection: Connection) -> None:
        """Release a connection back to the pool with optimized operations."""
        if connection.closed:
            self._connection_times.pop(connection, None)
            self._clear_health_cache(connection)
            return
        
        # Check if connection is still healthy before returning to pool
        if self.enable_health_check and not self._is_connection_healthy(connection):
            await connection.close()
            self._connection_times.pop(connection, None)
            self._clear_health_cache(connection)
            return
        
        scheme = connection.scheme or ("https" if connection.use_ssl else "http")
        key = self._make_key(scheme, connection.addr[0], connection.addr[1])
        queue = self._get_queue(key)
        lock = self._locks[key]
        
        # Update last used time
        self._connection_times[connection] = self._get_current_time()
        
        should_close = False
        async with lock:
            if len(queue) >= self.max_per_host:
                should_close = True
            else:
                queue.append(connection)
        if should_close:
            await connection.close()
            self._connection_times.pop(connection, None)
            self._clear_health_cache(connection)

    def get_stats(self) -> Dict[str, int]:
        """Get connection pool statistics for monitoring."""
        return self._stats.snapshot(
            current=len(self._connection_times),
            active_pools=len(self._pools),
            health_cache_size=len(self._health_cache),
        )
    
    def reset_stats(self) -> None:
        """Reset connection pool statistics."""
        self._stats = _PoolStats(peak_connections=len(self._connection_times))

    async def close(self) -> None:
        """Close all connections in the pool with optimized cleanup."""
        pools = list(self._pools.items())
        locks = self._locks.copy()
        self._pools.clear()
        self._locks.clear()
        
        # Close all connections efficiently
        for key, q in pools:
            lock = locks.get(key) or asyncio.Lock()
            async with lock:
                while q:
                    conn = q.pop()
                    await conn.close()
                    self._connection_times.pop(conn, None)
                    self._clear_health_cache(conn)
                    self._stats.total_connections_closed += 1
        
        self._connection_times.clear()
        self._health_cache.clear()

    async def cleanup_expired(self) -> None:
        """Remove expired connections from all pools more efficiently."""
        if not self.enable_health_check:
            return
        
        current_time = self._get_current_time()
        expired_connections = []
        
        # Find expired connections in a single pass
        for conn, last_used in list(self._connection_times.items()):
            if current_time - last_used > self.keepalive_timeout:
                expired_connections.append(conn)
        
        # Close expired connections and clean up caches
        for conn in expired_connections:
            await conn.close()
            self._connection_times.pop(conn, None)
            self._clear_health_cache(conn)
        
        # Clean up queues more efficiently with batch operations
        for key, queue in list(self._pools.items()):
            lock = self._locks[key]
            healthy_connections = []
            expired_in_queue = []
            
            async with lock:
                while queue:
                    conn = queue.pop()
                    if conn in expired_connections or not self._is_connection_healthy(conn):
                        expired_in_queue.append(conn)
                    else:
                        healthy_connections.append(conn)
                # Put healthy connections back respecting capacity
                for conn in healthy_connections:
                    if len(queue) >= self.max_per_host:
                        expired_in_queue.append(conn)
                    else:
                        queue.append(conn)
            
            # Close expired connections found in queue (outside lock)
            for conn in expired_in_queue:
                await conn.close()
                self._connection_times.pop(conn, None)
                self._clear_health_cache(conn)
        
        # Clear health cache periodically to prevent memory leaks
        if len(self._health_cache) > 1000:
            self._health_cache.clear()

