import asyncio
import ssl
import time
from functools import lru_cache
from typing import Dict, Optional, Tuple

import h11

from .errors import RequestError, ResponseError
from .request import Request
from .response import Response


# Cache SSL contexts to avoid repeated creation
_SSL_CONTEXT_CACHE: Dict[str, ssl.SSLContext] = {}

# Shared buffer size for network reads/writes
READ_BUFFER_SIZE = 65536


@lru_cache(maxsize=128)
def _get_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """Get or create cached SSL context."""
    cache_key = f"verify_{verify}"
    if cache_key not in _SSL_CONTEXT_CACHE:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        _SSL_CONTEXT_CACHE[cache_key] = context
    return _SSL_CONTEXT_CACHE[cache_key]

class Connection:
    """
    Async HTTP/1.1 connection built on asyncio streams + h11.

    We aggressively reuse buffers and caches so request/response cycles
    stay CPU + memory friendly even under heavy load.
    """

    def __init__(
        self,
        addr: Tuple[str, int],
        use_ssl: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        timeout: Optional[float] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        write_timeout: Optional[float] = None,
        verify: bool = True,
        scheme: str = "http",
    ) -> None:
        self.addr = addr
        self.use_ssl = use_ssl
        self.scheme = scheme
        # Optimize SSL context creation and reuse
        if use_ssl:
            self.ssl_context = ssl_context or _get_ssl_context(verify)
        else:
            self.ssl_context = None
        # Cache timeout values to avoid repeated attribute access
        self.timeout = timeout
        self.connect_timeout = connect_timeout or timeout
        self.read_timeout = read_timeout or timeout
        self.write_timeout = write_timeout or timeout
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter
        self.h11_conn = h11.Connection(h11.CLIENT)
        self.closed = False
        self._connected = False
        # Cache for encoded headers to avoid repeated encoding
        self._header_cache: Dict[str, Tuple[bytes, bytes]] = {}
        # Connection state optimization
        self._last_activity = 0
        self._bytes_sent = 0
        self._bytes_received = 0
        # Buffered writer state (reduces drain calls & syscalls)
        self._write_buffer = bytearray()
        self._pending_write = 0
        self._drain_threshold = READ_BUFFER_SIZE

    def _encode_headers(self, headers: Dict[str, str]) -> list:
        """Encode headers with caching to reduce memory allocations."""
        encoded_headers = []
        for k, v in headers.items():
            # Use cache for frequently used headers
            cache_key = f"{k}:{v}"
            if cache_key in self._header_cache:
                encoded_headers.append(self._header_cache[cache_key])
            else:
                encoded_pair = (k.encode("ascii"), v.encode("ascii"))
                self._header_cache[cache_key] = encoded_pair
                encoded_headers.append(encoded_pair)
        return encoded_headers

    def get_stats(self) -> Dict[str, int]:
        """Get connection statistics."""
        return {
            'bytes_sent': self._bytes_sent,
            'bytes_received': self._bytes_received,
            'header_cache_size': len(self._header_cache),
            'connected': self._connected,
            'closed': self.closed
        }

    def _update_activity(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Update connection activity statistics."""
        self._last_activity = time.time()
        self._bytes_sent += bytes_sent
        self._bytes_received += bytes_received

    async def connect(self) -> None:
        if self._connected:
            return
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.addr[0], self.addr[1], ssl=self.ssl_context if self.use_ssl else None),
            timeout=self.connect_timeout,
        )
        self._connected = True

    async def close(self) -> None:
        """Close connection with improved error handling and resource cleanup."""
        if self.closed:
            return
        self.closed = True
        self._connected = False
        # Clear caches to prevent memory leaks
        self._header_cache.clear()
        self._write_buffer.clear()
        self._pending_write = 0

        if hasattr(self, 'writer') and self.writer:
            try:
                self.writer.close()
                try:
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=5.0)
                except asyncio.TimeoutError:
                    # Force close if timeout occurs
                    pass
                except Exception:
                    # Ignore errors during cleanup
                    pass
            except Exception:
                # Writer might already be closed
                pass

    async def _send_event(self, event: h11.Event) -> None:
        """Serialize an h11 event and stage it for writing."""
        data = self.h11_conn.send(event)
        if not data:
            return
        self._update_activity(bytes_sent=len(data))
        self._write_buffer.extend(data)
        self._pending_write += len(data)
        if self._pending_write >= self._drain_threshold:
            await self._flush_writer()

    async def _send_chunked_body(self, body_iter) -> None:
        """Send chunked body with optimized buffer management."""
        async for part in body_iter:
            if not part:
                continue
            if isinstance(part, memoryview):
                part = part.tobytes()
            # Pre-allocate buffer for better performance
            chunk_size = len(part)
            chunk = bytearray(len(f"{chunk_size:x}\r\n") + chunk_size + 2)
            pos = 0
            # Write chunk size in hex
            size_hex = f"{chunk_size:x}"
            chunk[pos:pos+len(size_hex)] = size_hex.encode('ascii')
            pos += len(size_hex)
            # Write \r\n
            chunk[pos:pos+2] = b'\r\n'
            pos += 2
            # Write data
            chunk[pos:pos+chunk_size] = part
            pos += chunk_size
            # Write \r\n
            chunk[pos:pos+2] = b'\r\n'
            
            await self._send_event(h11.Data(data=bytes(chunk)))
        await self._send_event(h11.Data(data=b"0\r\n\r\n"))

    async def _flush_writer(self, force: bool = False) -> None:
        """
        Flush the staged bytes to the underlying transport.
        A force flush is used before reading the response to ensure all data
        is sent even if the threshold was not hit.
        """
        if not self._write_buffer:
            return
        if not force and self._pending_write < self._drain_threshold:
            return
        payload = bytes(self._write_buffer)
        self.writer.write(payload)
        try:
            if self.write_timeout is not None:
                await asyncio.wait_for(self.writer.drain(), timeout=self.write_timeout)
            else:
                await self.writer.drain()
        finally:
            self._write_buffer.clear()
            self._pending_write = 0

    async def send_request(self, request: Request, stream: bool = False) -> Response:
        """Send HTTP request and return the parsed Response."""
        if self.closed:
            raise RequestError("Connection already closed")
        await self.connect()
        try:
            # Use cached header encoding for better performance
            encoded_headers = self._encode_headers(request.headers)
            await self._send_event(
                h11.Request(
                    method=request.method.encode("ascii"),
                    target=request.target.encode("ascii"),
                    headers=encoded_headers,
                )
            )
            body_iter = request.iter_body()
            if body_iter is not None:
                await self._send_chunked_body(body_iter)
                await self._send_event(h11.EndOfMessage())
            else:
                body_bytes = request._content_bytes()
                if body_bytes:
                    await self._send_event(h11.Data(data=body_bytes))
                await self._send_event(h11.EndOfMessage())
            await self._flush_writer(force=True)
        except Exception as exc:  # pragma: no cover - network safety
            await self.close()
            raise RequestError(f"Failed to send request: {exc}") from exc

        return await self._read_response(request, stream=stream)

    async def _read_event(self) -> h11.Event:
        """Read HTTP event with optimized buffer management."""
        while True:
            event = self.h11_conn.next_event()
            if event is h11.NEED_DATA:
                # Use larger buffer for better performance
                try:
                    chunk = await asyncio.wait_for(self.reader.read(READ_BUFFER_SIZE), timeout=self.read_timeout)
                except asyncio.TimeoutError:
                    raise ResponseError("Read timeout")
                
                if not chunk:
                    raise ResponseError("Connection closed by peer")
                self._update_activity(bytes_received=len(chunk))
                self.h11_conn.receive_data(chunk)
                continue
            return event

    async def _read_response(self, request: Request, stream: bool = False) -> Response:
        """Read HTTP response with optimized header processing."""
        status_code = 0
        reason = b""
        headers = []
        body_chunks = []

        # Read response headers
        while True:
            event = await self._read_event()
            if isinstance(event, h11.Response):
                status_code = event.status_code
                reason = event.reason
                headers.extend(event.headers)
                break
            elif event is h11.ConnectionClosed:
                raise ResponseError("Connection closed before response")

        # Optimize header decoding with single pass
        decoded_headers = {}
        for k, v in headers:
            try:
                decoded_key = k.decode("ascii")
                decoded_value = v.decode("ascii")
                decoded_headers[decoded_key] = decoded_value
            except UnicodeDecodeError:
                # Fallback for non-ASCII headers
                decoded_headers[k.decode('utf-8', errors='replace')] = v.decode('utf-8', errors='replace')

        # Handle streaming response
        if stream:
            async def body_iter():
                try:
                    while True:
                        event = await self._read_event()
                        if isinstance(event, h11.Data):
                            yield event.data
                        elif isinstance(event, h11.EndOfMessage):
                            break
                        elif event is h11.ConnectionClosed:
                            break
                finally:
                    await self._finish_cycle()

            return Response(
                status_code=status_code,
                headers=decoded_headers,
                content=None,
                reason=reason.decode("ascii") if isinstance(reason, (bytes, bytearray)) else str(reason),
                request=request,
                connection=self,
                _aiter=body_iter(),
            )

        # Read non-streaming response body
        body_buffer = bytearray()
        while True:
            event = await self._read_event()
            if isinstance(event, h11.Data):
                body_buffer.extend(event.data)
            elif isinstance(event, h11.EndOfMessage):
                break
            elif event is h11.ConnectionClosed:
                break

        body = bytes(body_buffer)
        response = Response(
            status_code=status_code,
            headers=decoded_headers,
            content=body,
            reason=reason.decode("ascii") if isinstance(reason, (bytes, bytearray)) else str(reason),
            request=request,
            connection=self,
        )

        await self._finish_cycle()
        return response

    async def _finish_cycle(self) -> None:
        try:
            self.h11_conn.start_next_cycle()
        except h11.ProtocolError:
            await self.close()

