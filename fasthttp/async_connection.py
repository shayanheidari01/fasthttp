import asyncio
import ssl
from typing import Optional, Tuple

import h11

from .errors import RequestError, ResponseError
from .request import Request
from .response import Response


class AsyncConnection:
    """
    Async HTTP/1.1 connection built on asyncio streams and h11.
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
        if use_ssl:
            if ssl_context is not None:
                self.ssl_context = ssl_context
            else:
                self.ssl_context = ssl.create_default_context()
                if not verify:
                    self.ssl_context.check_hostname = False
                    self.ssl_context.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_context = None
        self.timeout = timeout
        self.connect_timeout = connect_timeout or timeout
        self.read_timeout = read_timeout or timeout
        self.write_timeout = write_timeout or timeout
        self.reader: asyncio.StreamReader
        self.writer: asyncio.StreamWriter
        self.h11_conn = h11.Connection(h11.CLIENT)
        self.closed = False
        self._connected = False

    async def connect(self) -> None:
        if self._connected:
            return
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.addr[0], self.addr[1], ssl=self.ssl_context if self.use_ssl else None),
            timeout=self.connect_timeout,
        )
        self._connected = True

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._connected:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass

    async def _send_event(self, event: h11.Event) -> None:
        data = self.h11_conn.send(event)
        if data:
            if self.write_timeout is not None:
                self.writer.write(data)
                await asyncio.wait_for(self.writer.drain(), timeout=self.write_timeout)
            else:
                self.writer.write(data)
                await self.writer.drain()

    async def _send_chunked_body(self, body_iter) -> None:
        async for part in body_iter:
            if not part:
                continue
            if isinstance(part, memoryview):
                part = part.tobytes()
            chunk = b"%x\r\n%s\r\n" % (len(part), part)
            await self._send_event(h11.Data(data=chunk))
        await self._send_event(h11.Data(data=b"0\r\n\r\n"))

    async def send_request(self, request: Request, stream: bool = False) -> Response:
        if self.closed:
            raise RequestError("Connection already closed")
        await self.connect()
        try:
            await self._send_event(
                h11.Request(
                    method=request.method.encode("ascii"),
                    target=request.target.encode("ascii"),
                    headers=[(k.encode("ascii"), v.encode("ascii")) for k, v in request.headers.items()],
                )
            )
            body_iter = request.aiter_body()
            if body_iter is not None:
                await self._send_chunked_body(body_iter)
                await self._send_event(h11.EndOfMessage())
            else:
                body_bytes = request._content_bytes()
                if body_bytes:
                    await self._send_event(h11.Data(data=body_bytes))
                await self._send_event(h11.EndOfMessage())
        except Exception as exc:  # pragma: no cover - network safety
            await self.close()
            raise RequestError(f"Failed to send request: {exc}") from exc

        return await self._read_response(request, stream=stream)

    async def _read_event(self) -> h11.Event:
        while True:
            event = self.h11_conn.next_event()
            if event is h11.NEED_DATA:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=self.read_timeout)
                if not chunk:
                    raise ResponseError("Connection closed by peer")
                self.h11_conn.receive_data(chunk)
                continue
            return event

    async def _read_response(self, request: Request, stream: bool = False) -> Response:
        status_code = 0
        reason = b""
        headers = []
        body_chunks = []

        while True:
            event = await self._read_event()
            if isinstance(event, h11.Response):
                status_code = event.status_code
                reason = event.reason
                headers.extend(event.headers)
                break
            elif event is h11.ConnectionClosed:
                raise ResponseError("Connection closed before response")

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
                headers={k.decode("ascii"): v.decode("ascii") for k, v in headers},
                content=None,
                reason=reason.decode("ascii") if isinstance(reason, (bytes, bytearray)) else str(reason),
                request=request,
                connection=self,
                _aiter=body_iter(),
            )

        while True:
            event = await self._read_event()
            if isinstance(event, h11.Data):
                body_chunks.append(event.data)
            elif isinstance(event, h11.EndOfMessage):
                break
            elif event is h11.ConnectionClosed:
                break

        body = b"".join(body_chunks)
        response = Response(
            status_code=status_code,
            headers={k.decode("ascii"): v.decode("ascii") for k, v in headers},
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
