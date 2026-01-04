"""maxhttp public API surface and sync convenience wrappers.

This module exposes the primary client classes, error hierarchy, and helper
functions, while also providing ready-to-use async convenience shortcuts
(e.g. :func:`get`, :func:`post`).  When imported, it automatically wraps the
async APIs so they can be consumed from synchronous code as well, mirroring
the ergonomics of popular HTTP clients while keeping the async-first core."""

import sys

from ._version import __version__ as __version__
from .client import Client
from .response import Response
from .request import Request
from .cookies import CookieJar, Cookie
from .retry import RetryPolicy
from .timeouts import Timeout
from .websocket import WebSocket
from .auth import AuthBase, BasicAuth, DigestAuth
from . import sync
from .errors import (
    MaxHTTPError,
    RequestError,
    ResponseError,
    HTTPStatusError,
    PoolError,
    WebSocketError,
    WebSocketHandshakeError,
    WebSocketClosed,
)

async def get(url: str, **kwargs) -> Response:
    """Perform a single GET request using a short-lived :class:`Client`."""
    async with Client() as client:
        return await client.get(url, **kwargs)

async def post(url: str, **kwargs) -> Response:
    """Perform a POST request with optional body helpers via :class:`Client`."""
    async with Client() as client:
        return await client.post(url, **kwargs)

async def put(url: str, **kwargs) -> Response:
    """Send a PUT request using a temporary :class:`Client` instance."""
    async with Client() as client:
        return await client.put(url, **kwargs)

async def delete(url: str, **kwargs) -> Response:
    """Issue a DELETE request and return the resulting :class:`Response`."""
    async with Client() as client:
        return await client.delete(url, **kwargs)

async def patch(url: str, **kwargs) -> Response:
    """Submit a PATCH request while reusing maxhttp's default configuration."""
    async with Client() as client:
        return await client.patch(url, **kwargs)

async def options(url: str, **kwargs) -> Response:
    """Query the remote server's supported methods via OPTIONS."""
    async with Client() as client:
        return await client.options(url, **kwargs)

async def head(url: str, **kwargs) -> Response:
    """Fetch headers for a resource using the HEAD method."""
    async with Client() as client:
        return await client.head(url, **kwargs)

async def trace(url: str, **kwargs) -> Response:
    """Send a TRACE request and capture the diagnostic response."""
    async with Client() as client:
        return await client.trace(url, **kwargs)

sync.wrap_methods(sys.modules[__name__])

__all__ = [
    "Client",
    "Response",
    "Request",
    "CookieJar",
    "Cookie",
    "RetryPolicy",
    "Timeout",
    "WebSocket",
    "AuthBase",
    "BasicAuth",
    "DigestAuth",
    "MaxHTTPError",
    "RequestError",
    "ResponseError",
    "HTTPStatusError",
    "PoolError",
    "WebSocketError",
    "WebSocketHandshakeError",
    "WebSocketClosed",
    "sync",
    "get",
    "post",
    "put",
    "__version__",
]