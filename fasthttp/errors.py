class FastHTTPError(Exception):
    """Base exception for the fasthttp package."""


class RequestError(FastHTTPError):
    """Raised when request building or sending fails."""


class ResponseError(FastHTTPError):
    """Raised when response parsing fails."""


class PoolError(FastHTTPError):
    """Raised when the connection pool cannot provide a connection."""


from typing import Optional


class HTTPStatusError(ResponseError):
    """Raised when a response has an HTTP error status (4xx or 5xx)."""

    def __init__(self, status_code: int, message: str, response: Optional[object] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response = response
