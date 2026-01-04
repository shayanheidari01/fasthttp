import asyncio
import ssl
import time
from collections import deque
from functools import lru_cache
from typing import AsyncIterator, Deque, Dict, Optional, Tuple

from .errors import HTTP2NotAvailable, RequestError, ResponseError
from .request import Request
from .response import Response

try:  # Optional dependency: hyper-h2
    from h2.connection import H2Connection
    from h2.config import H2Configuration
    from h2.events import (
        ConnectionTerminated,
        DataReceived,
        Event,
        InformationalResponseReceived,
        PingAckReceived,
        PingReceived,
        ResponseReceived,
        SettingsAcknowledged,
        StreamEnded,
        TrailersReceived,
        WindowUpdated,
    )
    from h2.errors import ErrorCodes
except ModuleNotFoundError as exc:  # pragma: no cover - import guard
    _H2_IMPORT_ERROR = exc
else:
    _H2_IMPORT_ERROR = None

READ_BUFFER_SIZE = 65536


@lru_cache(maxsize=32)
def _get_http2_ssl_context(verify: bool = True) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(["h2"])
    except NotImplementedError:  # pragma: no cover - very old openssl
        pass
    return context


if _H2_IMPORT_ERROR is not None:

    class HTTP2Connection:
        """
        Placeholder that surfaces a helpful error when hyper-h2 is missing.
        """

        def __init__(self, *args, **kwargs) -> None:  # pragma: no cover - trivial
            raise HTTP2NotAvailable(
                "hyper-h2 is not installed. Install maxhttp with the HTTP/2 extra: "
                "`pip install maxhttp[h2]`."
            ) from _H2_IMPORT_ERROR

else:

    class HTTP2Connection:
        """
        Minimal HTTP/2 client connection backed by hyper-h2.

        We support one in-flight stream per connection to keep parity with the
        HTTP/1.1 connection lifecycle used by the pool.
        """

        def __init__(
            self,
            addr: Tuple[str, int],
            *,
            scheme: str,
            ssl_context: Optional[ssl.SSLContext] = None,
            timeout: Optional[float] = None,
            connect_timeout: Optional[float] = None,
            read_timeout: Optional[float] = None,
            write_timeout: Optional[float] = None,
            verify: bool = True,
        ) -> None:
            if scheme != "https":
                raise RequestError("HTTP/2 is only supported over HTTPS transports.")

            self.addr = addr
            self.scheme = scheme
            self.use_ssl = True
            self.ssl_context = ssl_context or _get_http2_ssl_context(verify)
            self.verify = verify
            self.is_http2 = True

            self.timeout = timeout
            self.connect_timeout = connect_timeout or timeout
            self.read_timeout = read_timeout or timeout
            self.write_timeout = write_timeout or timeout

            self.reader: asyncio.StreamReader
            self.writer: asyncio.StreamWriter

            self.h2_conn = H2Connection(config=H2Configuration(client_side=True))
            self._event_buffer: Deque[Event] = deque()
            self._current_stream_id: Optional[int] = None
            self._stream_closed = True
            self._connected = False
            self.closed = False
            self._last_activity = 0.0
            self._pending_goaway_close = False

        def _update_activity(self, *, bytes_sent: int = 0, bytes_received: int = 0) -> None:
            self._last_activity = time.time()
            # Telemetry hooks placeholder. Kept for parity with HTTP/1 stats.
            _ = bytes_sent + bytes_received

        async def connect(self) -> None:
            if self._connected:
                return

            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.addr[0],
                        self.addr[1],
                        ssl=self.ssl_context,
                    ),
                    timeout=self.connect_timeout,
                )
            except asyncio.TimeoutError as exc:  # pragma: no cover - network
                raise RequestError("HTTP/2 connect timeout") from exc

            ssl_object = self.writer.get_extra_info("ssl_object")
            negotiated = ssl_object.selected_alpn_protocol() if ssl_object else None
            if negotiated != "h2":
                await self.close()
                raise HTTP2NotAvailable("Remote peer did not negotiate HTTP/2 via ALPN.")

            self.h2_conn.initiate_connection()
            await self._flush_outbound()

            self._connected = True

        async def close(self) -> None:
            if self.closed:
                return
            self.closed = True
            self._connected = False
            self._event_buffer.clear()
            try:
                if hasattr(self, "writer"):
                    self.writer.close()
                    await asyncio.wait_for(self.writer.wait_closed(), timeout=5.0)
            except Exception:  # pragma: no cover - defensive
                pass

        async def send_request(self, request: Request, stream: bool = False) -> Response:
            if self.closed:
                raise RequestError("HTTP/2 connection already closed")
            await self.connect()
            if self._current_stream_id is not None:
                raise RequestError("HTTP/2 connection is busy with another stream")

            headers = self._build_headers(request)
            body_iter = request.iter_body()
            body_bytes = None if body_iter is not None else request._content_bytes()
            has_body = body_iter is not None or (body_bytes is not None and len(body_bytes) > 0)

            stream_id = self.h2_conn.get_next_available_stream_id()
            self._current_stream_id = stream_id
            self._stream_closed = False

            self.h2_conn.send_headers(stream_id, headers, end_stream=not has_body)
            await self._flush_outbound()

            if has_body:
                if body_iter is not None:
                    await self._send_streaming_body(stream_id, body_iter)
                    await self._end_stream(stream_id)
                else:
                    await self._send_data(stream_id, body_bytes or b"", end_stream=True)

            return await self._receive_response(request, stream_id, request, stream)

        async def _send_streaming_body(self, stream_id: int, body_iter) -> None:
            async for part in body_iter:
                if not part:
                    continue
                if isinstance(part, memoryview):
                    part = part.tobytes()
                await self._send_data(stream_id, part, end_stream=False)

        async def _send_data(self, stream_id: int, data: bytes, *, end_stream: bool) -> None:
            view = memoryview(data)
            while view:
                await self._wait_for_flow_control(stream_id)
                chunk_size = min(
                    len(view),
                    self.h2_conn.local_flow_control_window(stream_id),
                    self.h2_conn.outbound_flow_control_window,
                    self.h2_conn.max_outbound_frame_size,
                )
                if chunk_size == 0:
                    # If both windows are zero we need to wait for WINDOW_UPDATE.
                    await self._wait_for_flow_control(stream_id)
                    continue

                chunk = view[:chunk_size].tobytes()
                view = view[chunk_size:]
                is_last_chunk = end_stream and len(view) == 0
                self.h2_conn.send_data(stream_id, chunk, end_stream=is_last_chunk)
                await self._flush_outbound()

            if end_stream and len(data) == 0:
                self.h2_conn.end_stream(stream_id)
                await self._flush_outbound()

        async def _end_stream(self, stream_id: int) -> None:
            self.h2_conn.end_stream(stream_id)
            await self._flush_outbound()

        async def _wait_for_flow_control(self, stream_id: int) -> None:
            while True:
                connection_window = self.h2_conn.outbound_flow_control_window
                stream_window = self.h2_conn.local_flow_control_window(stream_id)
                if connection_window > 0 and stream_window > 0:
                    return
                await self._read_into_buffer()

        async def _receive_response(self, original_request: Request, stream_id: int, request: Request, stream: bool) -> Response:
            status_code = 0
            headers = {}
            reason = ""
            informational_headers = []

            while True:
                event = await self._next_event()
                if isinstance(event, ResponseReceived) and event.stream_id == stream_id:
                    status_code, headers = self._decode_headers(event.headers)
                    break
                if isinstance(event, InformationalResponseReceived) and event.stream_id == stream_id:
                    informational_headers.append(event.headers)
                    continue
                await self._handle_event(event)

            if stream:
                response = Response(
                    status_code=status_code,
                    headers=headers,
                    content=None,
                    reason=reason,
                    request=original_request,
                    connection=self,
                    _aiter=self._streaming_body(stream_id),
                )
                response._http2_stream_id = stream_id  # type: ignore[attr-defined]
                return response

            body = bytearray()
            trailers = {}
            while True:
                event = await self._next_event()
                if isinstance(event, DataReceived) and event.stream_id == stream_id:
                    if event.data:
                        body.extend(event.data)
                    self.h2_conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
                    await self._flush_outbound()
                elif isinstance(event, TrailersReceived) and event.stream_id == stream_id:
                    trailers.update({k.decode("ascii"): v.decode("ascii") for k, v in event.headers})
                elif isinstance(event, StreamEnded) and event.stream_id == stream_id:
                    await self._mark_stream_finished(stream_id)
                    break
                else:
                    await self._handle_event(event)

            if trailers:
                headers.update(trailers)

            response = Response(
                status_code=status_code,
                headers=headers,
                content=bytes(body),
                reason=reason,
                request=original_request,
                connection=self,
            )
            return response

        async def _streaming_body(self, stream_id: int) -> AsyncIterator[bytes]:
            try:
                while True:
                    event = await self._next_event()
                    if isinstance(event, DataReceived) and event.stream_id == stream_id:
                        data = event.data
                        if data:
                            yield data
                        self.h2_conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
                        await self._flush_outbound()
                    elif isinstance(event, StreamEnded) and event.stream_id == stream_id:
                        await self._mark_stream_finished(stream_id)
                        break
                    else:
                        await self._handle_event(event)
            finally:
                await self._ensure_stream_closed(stream_id, cancel_if_open=False)

        async def _mark_stream_finished(self, stream_id: int) -> None:
            self._stream_closed = True
            self._current_stream_id = None
            if self._pending_goaway_close:
                self._pending_goaway_close = False
                await self.close()

        async def _ensure_stream_closed(self, stream_id: int, *, cancel_if_open: bool) -> None:
            if self._stream_closed:
                self._current_stream_id = None
                if self._pending_goaway_close:
                    self._pending_goaway_close = False
                    await self.close()
                return
            if cancel_if_open:
                try:
                    self.h2_conn.reset_stream(stream_id, error_code=ErrorCodes.CANCEL)
                    await self._flush_outbound()
                except Exception:
                    pass
            self._current_stream_id = None
            self._stream_closed = True

        async def cancel_active_stream(self) -> None:
            if self._current_stream_id is None:
                return
            await self._ensure_stream_closed(self._current_stream_id, cancel_if_open=True)

        async def _next_event(self) -> Event:
            while True:
                if self._event_buffer:
                    return self._event_buffer.popleft()
                await self._read_into_buffer()

        async def _read_into_buffer(self) -> None:
            try:
                data = await asyncio.wait_for(self.reader.read(READ_BUFFER_SIZE), timeout=self.read_timeout)
            except asyncio.TimeoutError as exc:
                raise ResponseError("HTTP/2 read timeout") from exc
            if not data:
                raise ResponseError("HTTP/2 connection closed by peer")
            self._update_activity(bytes_received=len(data))
            events = self.h2_conn.receive_data(data)
            self._event_buffer.extend(events)
            await self._flush_outbound()

        async def _flush_outbound(self) -> None:
            data = self.h2_conn.data_to_send()
            if not data:
                return
            self._update_activity(bytes_sent=len(data))
            self.writer.write(data)
            try:
                if self.write_timeout is not None:
                    await asyncio.wait_for(self.writer.drain(), timeout=self.write_timeout)
                else:
                    await self.writer.drain()
            except asyncio.TimeoutError as exc:
                raise RequestError("HTTP/2 write timeout") from exc

        async def _handle_event(self, event: Event) -> None:
            if isinstance(event, PingReceived):
                self.h2_conn.ping_ack(event.ping_data)
                await self._flush_outbound()
            elif isinstance(event, PingAckReceived):
                return
            elif isinstance(event, WindowUpdated):
                return
            elif isinstance(event, SettingsAcknowledged):
                return
            elif isinstance(event, ConnectionTerminated):
                last_stream_id = getattr(event, "last_stream_id", -1)
                if (
                    event.error_code == ErrorCodes.NO_ERROR
                    and self._current_stream_id is not None
                    and last_stream_id >= self._current_stream_id
                ):
                    # Server is performing a graceful shutdown but will finish our in-flight stream.
                    self._pending_goaway_close = True
                    return
                await self.close()
                if event.error_code == ErrorCodes.NO_ERROR:
                    raise ResponseError("HTTP/2 connection closed before completing the active stream")
                raise ResponseError(f"HTTP/2 connection terminated: {event.error_code}")
            elif isinstance(event, DataReceived):
                # Data for a stream we are not actively reading. Acknowledge to keep flow control moving.
                self.h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                await self._flush_outbound()
            elif isinstance(event, StreamEnded):
                # Stream ended before we started consuming (rare). Clean up.
                await self._mark_stream_finished(event.stream_id)

        def _decode_headers(self, raw_headers) -> Tuple[int, Dict[str, str]]:
            status_code = 0
            headers: Dict[str, str] = {}
            for name, value in raw_headers:
                if name == b":status":
                    status_code = int(value.decode("ascii"))
                    continue
                if name.startswith(b":"):
                    continue
                headers[name.decode("ascii")] = value.decode("ascii")
            return status_code, headers

        def _build_headers(self, request: Request):
            authority = request.headers.get("Host") or request.headers.get("host")
            if not authority:
                authority = request.host
            header_list = [
                (b":method", request.method.encode("ascii")),
                (b":scheme", request.scheme.encode("ascii")),
                (b":authority", authority.encode("ascii")),
                (b":path", request.target.encode("ascii")),
            ]

            skip = {"host", "connection", "transfer-encoding"}
            for name, value in request.headers.items():
                lname = name.lower()
                if lname in skip:
                    continue
                header_list.append((lname.encode("ascii"), value.encode("ascii")))
            return header_list


__all__ = ["HTTP2Connection"]
