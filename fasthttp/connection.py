import socket
import ssl
from typing import Optional, Tuple

import h11

from .errors import RequestError, ResponseError
from .request import Request
from .response import Response


class Connection:
    """
    A lightweight HTTP/1.1 connection built on sockets and h11 state machine.
    """

    def __init__(
        self,
        addr: Tuple[str, int],
        use_ssl: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        connect_timeout: Optional[float] = None,
        read_timeout: Optional[float] = None,
        write_timeout: Optional[float] = None,
        verify: bool = True,
        scheme: str = "http",
    ) -> None:
        self.addr = addr
        self.use_ssl = use_ssl
        self.scheme = scheme
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
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
        raw_sock = socket.create_connection(addr, timeout=connect_timeout)
        if use_ssl:
            raw_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=addr[0])
        self.sock = raw_sock
        if read_timeout is not None:
            self.sock.settimeout(read_timeout)
        self.h11_conn = h11.Connection(h11.CLIENT)
        self.closed = False

    def close(self) -> None:
        if not self.closed:
            try:
                self.sock.close()
            finally:
                self.closed = True

    def _send_event(self, event: h11.Event) -> None:
        data = self.h11_conn.send(event)
        if data:
            if self.write_timeout is not None:
                self.sock.settimeout(self.write_timeout)
            self.sock.sendall(data)

    def _send_chunked_body(self, body_iter) -> None:
        for part in body_iter:
            if not part:
                continue
            if isinstance(part, memoryview):
                part = part.tobytes()
            chunk = b"%x\r\n%s\r\n" % (len(part), part)
            self._send_event(h11.Data(data=chunk))
        # terminating chunk
        self._send_event(h11.Data(data=b"0\r\n\r\n"))

    def send_request(self, request: Request, stream: bool = False) -> Response:
        if self.closed:
            raise RequestError("Connection already closed")
        try:
            self._send_event(
                h11.Request(
                    method=request.method.encode("ascii"),
                    target=request.target.encode("ascii"),
                    headers=[(k.encode("ascii"), v.encode("ascii")) for k, v in request.headers.items()],
                )
            )
            body_iter = request.iter_body()
            if body_iter is not None:
                self._send_chunked_body(body_iter)
                self._send_event(h11.EndOfMessage())
            else:
                body_bytes = request._content_bytes()
                if body_bytes:
                    self._send_event(h11.Data(data=body_bytes))
                self._send_event(h11.EndOfMessage())
        except Exception as exc:  # pragma: no cover - network safety
            self.close()
            raise RequestError(f"Failed to send request: {exc}") from exc

        return self._read_response(request, stream=stream)

    def _read_event(self) -> h11.Event:
        while True:
            event = self.h11_conn.next_event()
            if event is h11.NEED_DATA:
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout as exc:  # pragma: no cover - network timing
                    raise ResponseError("Read timeout") from exc
                if not chunk:
                    raise ResponseError("Connection closed by peer")
                self.h11_conn.receive_data(chunk)
                continue
            return event

    def _finish_cycle(self) -> None:
        try:
            self.h11_conn.start_next_cycle()
        except h11.ProtocolError:
            self.close()

    def _read_response(self, request: Request, stream: bool = False) -> Response:
        status_code = 0
        reason = b""
        headers = []
        body_chunks = []

        # First response headers
        while True:
            event = self._read_event()
            if isinstance(event, h11.Response):
                status_code = event.status_code
                reason = event.reason
                headers.extend(event.headers)
                break
            elif event is h11.ConnectionClosed:
                raise ResponseError("Connection closed before response")

        if stream:
            def body_iter():
                try:
                    while True:
                        event = self._read_event()
                        if isinstance(event, h11.Data):
                            yield event.data
                        elif isinstance(event, h11.EndOfMessage):
                            break
                        elif event is h11.ConnectionClosed:
                            break
                finally:
                    self._finish_cycle()

            return Response(
                status_code=status_code,
                headers={k.decode("ascii"): v.decode("ascii") for k, v in headers},
                content=None,
                reason=reason.decode("ascii") if isinstance(reason, (bytes, bytearray)) else str(reason),
                request=request,
                connection=self,
                _iter=body_iter(),
            )

        while True:
            event = self._read_event()
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

        self._finish_cycle()
        return response
