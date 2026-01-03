import asyncio
import contextlib
import json
import ssl
from collections import deque
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Union
from urllib.parse import urlparse

from .connection import READ_BUFFER_SIZE, _get_ssl_context
from .errors import (
    WebSocketClosed,
    WebSocketDecodeError,
    WebSocketError,
    WebSocketHandshakeError,
    WebSocketMessageTypeError,
    WebSocketProtocolError,
)
from .timeouts import Timeout
from wsproto import WSConnection
from wsproto.connection import ConnectionState, ConnectionType
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Event,
    Ping,
    Pong,
    RejectConnection,
    RejectData,
    Request,
    TextMessage,
)

HeadersType = Optional[Dict[str, str]]
SubprotocolsType = Optional[Sequence[str]]
ExtensionsType = Optional[Sequence]
JsonDumps = Optional[Callable[[Any], str]]
JsonLoads = Optional[Callable[[str], Any]]


class _WebSocketConnector:
    __slots__ = ("_cls", "_kwargs", "_instance")

    def __init__(self, cls, **kwargs):
        self._cls = cls
        self._kwargs = kwargs
        self._instance: Optional["WebSocket"] = None

    async def _connect(self) -> "WebSocket":
        if self._instance is None:
            self._instance = await self._cls._connect_impl(**self._kwargs)
        return self._instance

    def __await__(self):
        return self._connect().__await__()

    async def __aenter__(self) -> "WebSocket":
        return await self._connect()

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._instance is not None and not self._instance.closed:
            await self._instance.close()


class WebSocket:
    """
    High-level asynchronous WebSocket client built on wsproto.

    Provides minimal send/receive helpers while exposing access to negotiated
    subprotocols and extensions. Instances are async context managers to ensure
    transports close cleanly.
    """

    def __init__(
        self,
        *,
        url: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ws: WSConnection,
        timeout: Timeout,
        subprotocol: Optional[str],
        extensions: Sequence,
    ) -> None:
        self.url = url
        self._reader = reader
        self._writer = writer
        self._ws = ws
        self._timeout = timeout
        self.subprotocol = subprotocol
        self.extensions = list(extensions)
        self._event_buffer: Deque[Event] = deque()
        self._closed = False
        self._closing = False
        self._read_timeout = timeout.read or timeout.total
        self._write_timeout = timeout.write or timeout.total
        self._total_timeout = timeout.total

    # --------------------------------------------------------------------- #
    # Public API
    # --------------------------------------------------------------------- #
    @classmethod
    def connect(
        cls,
        url: str,
        *,
        headers: HeadersType = None,
        subprotocols: SubprotocolsType = None,
        extensions: ExtensionsType = None,
        timeout: Optional[Union[Timeout, float, int]] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> _WebSocketConnector:
        """
        Establish a websocket connection and return a WebSocket instance.

        Can be awaited directly::

            ws = await WebSocket.connect("wss://example.org/socket")

        Or used as an async context manager::

            async with WebSocket.connect("wss://example.org/socket") as ws:
                ...
        """
        return _WebSocketConnector(
            cls,
            url=url,
            headers=headers,
            subprotocols=subprotocols,
            extensions=extensions,
            timeout=timeout,
            verify=verify,
            ssl_context=ssl_context,
        )

    @classmethod
    async def _connect_impl(
        cls,
        url: str,
        *,
        headers: HeadersType = None,
        subprotocols: SubprotocolsType = None,
        extensions: ExtensionsType = None,
        timeout: Optional[Union[Timeout, float, int]] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> "WebSocket":
        timeout_cfg = Timeout.from_value(timeout)
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.hostname:
            raise WebSocketProtocolError(f"Invalid WebSocket URL: {url}")
        scheme = parsed.scheme.lower()
        if scheme not in ("ws", "wss"):
            raise WebSocketProtocolError(f"Unsupported WebSocket scheme '{scheme}'")

        port = parsed.port
        if port is None:
            port = 443 if scheme == "wss" else 80

        host = parsed.hostname
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"

        host_header = host
        default_port = 443 if scheme == "wss" else 80
        if port != default_port:
            host_header = f"{host_header}:{port}"

        stream_ssl = None
        if scheme == "wss":
            if ssl_context is not None:
                stream_ssl = ssl_context
            else:
                stream_ssl = _get_ssl_context(verify)

        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        connect_timeout = timeout_cfg.connect or timeout_cfg.total
        try:
            if connect_timeout is not None:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=stream_ssl),
                    timeout=connect_timeout,
                )
            else:
                reader, writer = await asyncio.open_connection(
                    host, port, ssl=stream_ssl
                )
        except asyncio.TimeoutError as exc:  # pragma: no cover - safety
            raise WebSocketError("WebSocket connect timeout") from exc
        except Exception as exc:  # pragma: no cover - network safety
            raise WebSocketError(f"Failed to connect to {url}: {exc}") from exc

        ws_conn = WSConnection(ConnectionType.CLIENT)
        extra_headers = cls._encode_headers(headers)
        request_event = Request(
            host=host_header,
            target=target,
            subprotocols=list(subprotocols or []),
            extensions=list(extensions or []),
            extra_headers=extra_headers,
        )
        await cls._write(writer, ws_conn.send(request_event), timeout_cfg)
        try:
            accept_event = await cls._perform_handshake(ws_conn, reader, timeout_cfg)
        except Exception:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            raise
        instance = cls(
            url=url,
            reader=reader,
            writer=writer,
            ws=ws_conn,
            timeout=timeout_cfg,
            subprotocol=accept_event.subprotocol,
            extensions=accept_event.extensions,
        )
        instance._buffer_events()
        return instance

    @property
    def closed(self) -> bool:
        return self._closed

    async def send_text(self, data: str, *, final: bool = True) -> None:
        """
        Send a text message (UTF-8 string).
        """
        if self._closed:
            raise WebSocketClosed(code=1006, reason="WebSocket already closed")
        event = TextMessage(data=data, message_finished=final)
        await self._send_event(event)

    async def send_bytes(self, data: Union[bytes, bytearray], *, final: bool = True) -> None:
        """
        Send a binary message.
        """
        if self._closed:
            raise WebSocketClosed(code=1006, reason="WebSocket already closed")
        event = BytesMessage(data=bytes(data), message_finished=final)
        await self._send_event(event)

    async def send_json(self, data: Any, *, dumps: JsonDumps = None) -> None:
        """
        Serialize *data* as JSON and send it as a TEXT message.
        """
        serializer = dumps or json.dumps
        await self.send_text(serializer(data))

    async def ping(self, payload: bytes = b"") -> None:
        """
        Send a ping frame.
        """
        if self._closed:
            raise WebSocketClosed(code=1006, reason="WebSocket already closed")
        await self._send_event(Ping(payload=payload))

    async def close(self, code: int = 1000, reason: Optional[str] = None) -> None:
        """
        Initiate a graceful close handshake.
        """
        if self._closed:
            return
        self._closing = True
        try:
            await self._send_event(CloseConnection(code=code, reason=reason))
            await self._drain_until_closed()
        finally:
            self._closed = True
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()

    async def recv(self) -> Union[str, bytes]:
        """
        Receive the next completed message.

        Returns:
            str for TEXT messages, bytes for BINARY.
        Raises:
            WebSocketClosed when the connection has been closed.
        """
        while True:
            event = await self._next_event()
            if isinstance(event, TextMessage):
                return event.data
            if isinstance(event, BytesMessage):
                return bytes(event.data)
            if isinstance(event, CloseConnection):
                await self._handle_remote_close(event)
                raise WebSocketClosed(code=event.code, reason=event.reason)
            if isinstance(event, Ping):
                await self._send_event(Pong(payload=event.payload))
                continue
            if isinstance(event, Pong):
                continue

    async def recv_text(self) -> str:
        """
        Receive the next message and ensure it is TEXT.
        """
        data = await self.recv()
        if isinstance(data, str):
            return data
        raise WebSocketMessageTypeError("TEXT", "BINARY")

    async def recv_bytes(self) -> bytes:
        """
        Receive the next message and ensure it is BINARY.
        """
        data = await self.recv()
        if isinstance(data, bytes):
            return data
        raise WebSocketMessageTypeError("BINARY", "TEXT")

    def __aiter__(self):
        return self

    async def __anext__(self) -> Union[str, bytes]:
        try:
            return await self.recv()
        except WebSocketClosed as exc:
            raise StopAsyncIteration from exc

    async def __aenter__(self) -> "WebSocket":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def recv_json(self, *, loads: JsonLoads = None) -> Any:
        """
        Receive the next TEXT/BINARY message and decode it as JSON.
        """
        parser = loads or json.loads
        data = await self.recv()
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WebSocketDecodeError(
                    "Cannot decode binary WebSocket payload as UTF-8 for JSON parsing"
                ) from exc
        try:
            return parser(data)
        except (TypeError, ValueError) as exc:
            raise WebSocketDecodeError("Received non-JSON WebSocket payload") from exc

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _encode_headers(headers: HeadersType) -> List[tuple[bytes, bytes]]:
        if not headers:
            return []
        encoded = []
        for key, value in headers.items():
            encoded.append((key.lower().encode("ascii"), value.encode("ascii")))
        return encoded

    @staticmethod
    async def _write(
        writer: asyncio.StreamWriter,
        data: bytes,
        timeout_cfg: Timeout,
    ) -> None:
        if not data:
            return
        writer.write(data)
        drain_timeout = timeout_cfg.write or timeout_cfg.total
        try:
            if drain_timeout is not None:
                await asyncio.wait_for(writer.drain(), timeout=drain_timeout)
            else:
                await writer.drain()
        except asyncio.TimeoutError as exc:  # pragma: no cover - safety
            raise WebSocketError("Write timeout") from exc

    @classmethod
    async def _perform_handshake(
        cls,
        ws_conn: WSConnection,
        reader: asyncio.StreamReader,
        timeout_cfg: Timeout,
    ) -> AcceptConnection:
        rejection_status: Optional[int] = None
        rejection_body = bytearray()
        while True:
            for event in ws_conn.events():
                if isinstance(event, AcceptConnection):
                    return event
                if isinstance(event, CloseConnection):
                    raise WebSocketHandshakeError(
                        f"Server closed connection during handshake ({event.code})"
                    )
                if isinstance(event, RejectConnection):
                    rejection_status = event.status_code
                    if not event.has_body:
                        raise WebSocketHandshakeError(
                            f"WebSocket handshake rejected ({event.status_code})"
                        )
                    continue
                if isinstance(event, RejectData):
                    rejection_body.extend(event.data)
                    if event.body_finished:
                        status = rejection_status or 400
                        body_text = rejection_body.decode("utf-8", errors="ignore")
                        raise WebSocketHandshakeError(
                            f"WebSocket handshake rejected ({status}): {body_text}"
                        )
                    continue
                if isinstance(event, Pong):
                    continue
            data = await cls._read(reader, timeout_cfg)
            if data is None:
                ws_conn.receive_data(None)
            else:
                ws_conn.receive_data(data)

    @staticmethod
    async def _read(reader: asyncio.StreamReader, timeout_cfg: Timeout) -> Optional[bytes]:
        read_timeout = timeout_cfg.read or timeout_cfg.total
        try:
            if read_timeout is not None:
                data = await asyncio.wait_for(reader.read(READ_BUFFER_SIZE), read_timeout)
            else:
                data = await reader.read(READ_BUFFER_SIZE)
        except asyncio.TimeoutError as exc:  # pragma: no cover - safety
            raise WebSocketError("Read timeout") from exc
        if data == b"":
            return None
        return data

    def _buffer_events(self) -> None:
        for event in self._ws.events():
            self._event_buffer.append(event)

    async def _next_event(self) -> Event:
        if self._event_buffer:
            return self._event_buffer.popleft()
        await self._read_into_buffer()
        if not self._event_buffer:
            raise WebSocketClosed(code=1006, reason="WebSocket connection closed")
        return self._event_buffer.popleft()

    async def _read_into_buffer(self) -> None:
        data = await self._read(self._reader, self._timeout)
        if data is None:
            self._ws.receive_data(None)
        else:
            self._ws.receive_data(data)
        self._buffer_events()

    async def _send_event(self, event: Event) -> None:
        payload = self._ws.send(event)
        await self._write(self._writer, payload, self._timeout)

    async def _drain_until_closed(self) -> None:
        if self._ws.state is ConnectionState.CLOSED:
            return
        try:
            await asyncio.wait_for(self._wait_for_close_frame(), timeout=1.0)
        except asyncio.TimeoutError:
            pass

    async def _wait_for_close_frame(self) -> None:
        while self._ws.state is not ConnectionState.CLOSED:
            await self._read_into_buffer()
            if not self._event_buffer:
                break
            event = self._event_buffer.popleft()
            if isinstance(event, CloseConnection):
                await self._handle_remote_close(event)
                break
            if isinstance(event, Ping):
                await self._send_event(Pong(payload=event.payload))

    async def _handle_remote_close(self, event: CloseConnection) -> None:
        if not self._closing:
            await self._send_event(event.response())
        self._closed = True
        self._writer.close()
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()


__all__ = ["WebSocket"]
