from typing import Optional


class MaxHTTPError(Exception):
    """Base exception for the maxhttp package."""


class RequestError(MaxHTTPError):
    """Raised when request building or sending fails."""


class ResponseError(MaxHTTPError):
    """Raised when response parsing fails."""


class HTTP2NotAvailable(RequestError):
    """Raised when HTTP/2 cannot be negotiated and the client should fall back."""


class PoolError(MaxHTTPError):
    """Raised when the connection pool cannot provide a connection."""


class WebSocketError(MaxHTTPError):
    """Base class for WebSocket-related errors."""


class WebSocketHandshakeError(WebSocketError):
    """Raised when the WebSocket HTTP upgrade handshake fails."""


class WebSocketClosed(WebSocketError):
    """Raised when operations are attempted on a closed WebSocket."""

    def __init__(self, code: int, reason: Optional[str] = None) -> None:
        self.code = code
        self.reason = reason
        message = f"WebSocket closed (code={code}, reason={reason or 'none'})"
        super().__init__(message)


class WebSocketProtocolError(WebSocketError):
    """Raised when protocol invariants are violated."""


class WebSocketMessageTypeError(WebSocketError):
    """Raised when a received frame type does not match what was expected."""

    def __init__(self, expected: str, actual: str) -> None:
        message = f"Expected {expected} WebSocket message but received {actual}"
        super().__init__(message)
        self.expected = expected
        self.actual = actual


class WebSocketDecodeError(WebSocketError):
    """Raised when frame payloads cannot be decoded into the requested format."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class HTTPStatusError(ResponseError):
    """Raised when a response has an HTTP error status (4xx or 5xx)."""

    def __init__(
        self,
        status_code: int,
        message: str,
        response: Optional[object] = None,
        *,
        reason: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response
        self.reason = reason
        self.detail = detail
