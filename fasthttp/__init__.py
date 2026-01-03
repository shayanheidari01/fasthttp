import sys

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
    FastHTTPError,
    RequestError,
    ResponseError,
    HTTPStatusError,
    PoolError,
    WebSocketError,
    WebSocketHandshakeError,
    WebSocketClosed,
)

async def get(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.get(url, **kwargs)

async def post(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.post(url, **kwargs)

async def put(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.put(url, **kwargs)

async def delete(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.delete(url, **kwargs)

async def patch(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.patch(url, **kwargs)

async def options(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.options(url, **kwargs)

async def head(url: str, **kwargs) -> Response:
    async with Client() as client:
        return await client.head(url, **kwargs)

async def trace(url: str, **kwargs) -> Response:
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
    "FastHTTPError",
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
    "delete",
    "patch",
    "options",
    "head",
    "trace",
]

__version__ = "0.1.7"
