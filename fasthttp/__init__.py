from .client import Client
from .response import Response
from .request import Request
from .cookies import CookieJar, Cookie
from .retry import RetryPolicy
from .timeouts import Timeout
from .errors import (
    FastHTTPError,
    RequestError,
    ResponseError,
    HTTPStatusError,
    PoolError,
)

__all__ = [
    "Client",
    "Response",
    "Request",
    "CookieJar",
    "Cookie",
    "RetryPolicy",
    "Timeout",
    "FastHTTPError",
    "RequestError",
    "ResponseError",
    "HTTPStatusError",
    "PoolError",
]


__version__ = "0.1.1"


def enable_sync():
    """
    Enable synchronous wrappers for all async classes.
    Call this function to make async methods available as sync methods.
    
    Example:
        from fasthttp import Client, enable_sync
        
        enable_sync()
        
        # Now you can use Client synchronously
        with Client(base_url="https://api.example.com") as client:
            resp = client.get("/users")  # No await needed
            data = resp.json()
    """
    from .sync import enable_sync as _enable_sync
    _enable_sync()


