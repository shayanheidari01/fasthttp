import asyncio
import fasthttp
import json as _json_module
import logging
import ssl
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qs

from .pool import ConnectionPool
from .request import Request
from .response import Response
from .retry import RetryPolicy
from .logging import get_logger
from .cookies import CookieJar
from .errors import RequestError


class Client:
    """
    Async HTTP/1.1 client with connection pooling, retry logic, cookie management,
    and support for JSON/form data.
    
    Features:
    - Connection pooling with health checks
    - Automatic retry with exponential backoff
    - Circuit breaker support
    - Cookie jar with full RFC 6265 compliance
    - JSON and form-encoded body support
    - Query parameter support
    - Redirect following
    - Streaming responses
    - Elapsed time tracking
    - Redirect history tracking
    
    Example:
        async with Client(base_url="https://api.example.com") as client:
            resp = await client.get("/users", params={"page": 1})
            data = resp.json()
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        pool: Optional[ConnectionPool] = None,
        timeout: Optional[float] = None,
        retry: Optional[RetryPolicy] = None,
        logger: Optional[logging.Logger] = None,
        cookies: Optional[CookieJar] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        self.base_url = base_url
        self.pool = pool or ConnectionPool()
        self.timeout = timeout
        self.retry = retry or RetryPolicy(max_attempts=1)
        self.logger = logger or get_logger()
        self.cookies = cookies or CookieJar()
        self.user_agent = user_agent or "fasthttp/{}".format(fasthttp.__version__)
        # Cache for header lookups to avoid repeated lowercase conversions
        self._header_cache: Dict[int, Dict[str, str]] = {}

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        params: Optional[Dict[str, Union[str, int, float, None]]] = None,
        timeout: Optional[float] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
        stream: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> Response:
        # Build URL with query parameters
        current_url = urljoin(self.base_url, url) if self.base_url else url
        if params:
            current_url = self._build_url_with_params(current_url, params)
        
        method = method.upper()
        resolved_timeout = timeout or self.timeout
        
        # Handle body content (json, data, or content)
        # Note: 'json' parameter shadows the json module, so we use it before assignment
        json_data = json
        form_data = data
        if json_data is not None:
            if content is not None or form_data is not None:
                raise ValueError("Cannot specify 'content' or 'data' together with 'json'")
            current_content = _json_module.dumps(json_data).encode("utf-8")
            current_headers = headers or {}
            if "content-type" not in {k.lower() for k in current_headers}:
                current_headers["Content-Type"] = "application/json"
        elif form_data is not None:
            if content is not None:
                raise ValueError("Cannot specify both 'content' and 'data' parameters")
            # Form-encoded data
            current_content = urlencode({k: str(v) for k, v in form_data.items() if v is not None}).encode("utf-8")
            current_headers = headers or {}
            if "content-type" not in {k.lower() for k in current_headers}:
                current_headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            current_content = content
            current_headers = headers or {}
        
        redirect_codes = {301, 302, 303, 307, 308}
        redirects = 0
        response_history: List[Response] = []
        start_time = time.time()

        while True:
            hdrs = self._inject_cookies(current_headers, current_url)
            # Add User-Agent if not present
            if not self._has_header(hdrs, "user-agent"):
                hdrs["User-Agent"] = self.user_agent
            
            req = Request(
                method=method,
                url=current_url,
                headers=hdrs,
                content=current_content,
                timeout=resolved_timeout,
            )
            # Circuit breaker: short-circuit if host is currently open
            if self.retry.is_circuit_open(req.host):
                raise RequestError(f"Circuit open for host {req.host}")

            conn = await self.pool.acquire(
                req.scheme,
                req.host,
                req.port,
                timeout=req.timeout,
                verify=verify,
                ssl_context=ssl_context,
            )
            attempts = 0
            delays = list(self.retry.iter_delays())
            request_start_time = time.time()
            while True:
                attempts += 1
                try:
                    resp = await conn.send_request(req, stream=stream)
                    # Set elapsed time
                    resp._set_elapsed(time.time() - request_start_time)
                    resp._history = response_history.copy()
                except self.retry.retry_exceptions as exc:
                    # On exception, possibly retry; if we end up giving up, record failure for circuit breaker
                    if attempts > self.retry.max_attempts:
                        self.retry.record_failure(req.host)
                        await conn.close()
                        raise
                    if delays:
                        delay = delays.pop(0)
                        self.logger.warning(f"[async] Retrying due to exception: {exc}; attempt {attempts}")
                        await conn.close()
                        await self._sleep(delay)
                        conn = await self.pool.acquire(
                            req.scheme,
                            req.host,
                            req.port,
                            timeout=req.timeout,
                            verify=verify,
                            ssl_context=ssl_context,
                        )
                        continue
                    self.retry.record_failure(req.host)
                    await conn.close()
                    raise

                if not stream and self.retry.should_retry_status(resp.status_code) and attempts < self.retry.max_attempts:
                    delay = delays.pop(0) if delays else 0
                    self.logger.warning(f"[async] Retrying due to status {resp.status_code}; attempt {attempts}")
                    await conn.close()
                    if delay:
                        await self._sleep(delay)
                    conn = await self.pool.acquire(
                        req.scheme,
                        req.host,
                        req.port,
                        timeout=req.timeout,
                        verify=verify,
                        ssl_context=ssl_context,
                    )
                    continue

                # Success (or non-retryable status on final attempt): record success or failure
                if not self.retry.should_retry_status(resp.status_code):
                    self.retry.record_success(req.host)
                else:
                    self.retry.record_failure(req.host)
                break

            self.cookies.add_from_response(resp)

            connection_header = resp.headers.get("Connection", resp.headers.get("connection", "keep-alive")).lower()
            should_close = connection_header == "close" or conn.closed
            if stream:
                async def _release_conn():
                    if should_close:
                        await conn.close()
                    else:
                        await self.pool.release(conn)

                resp._release = _release_conn
                return resp

            if should_close:
                await conn.close()
            else:
                await self.pool.release(conn)

            if follow_redirects and not stream and resp.status_code in redirect_codes:
                if redirects >= max_redirects:
                    raise RequestError("Too many redirects")
                # Use get with case-insensitive lookup for Location header
                location = resp.headers.get("Location") or resp.headers.get("location")
                if not location:
                    resp._history = response_history
                    resp._set_elapsed(time.time() - start_time)
                    return resp
                redirects += 1
                # Add to history before redirecting
                response_history.append(resp)
                new_url = urljoin(current_url, location)
                if resp.status_code in {301, 302, 303}:
                    method = "GET"
                    current_content = None
                    json_data = None  # Reset JSON data too
                    form_data = None  # Reset form data too
                    # Optimize header filtering by creating new dict only when needed
                    if current_headers:
                        current_headers = {k: v for k, v in current_headers.items() 
                                         if k.lower() not in ("content-length", "transfer-encoding")}
                    else:
                        current_headers = {}
                current_url = new_url
                continue

            # Set final elapsed time and history
            resp._history = response_history
            resp._set_elapsed(time.time() - start_time)
            return resp

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        **kwargs
    ) -> Response:
        return await self.request("POST", url, content=content, json=json, data=data, **kwargs)

    async def put(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        **kwargs
    ) -> Response:
        return await self.request("PUT", url, content=content, json=json, data=data, **kwargs)

    async def delete(self, url: str, **kwargs) -> Response:
        return await self.request("DELETE", url, **kwargs)

    async def patch(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        **kwargs
    ) -> Response:
        return await self.request("PATCH", url, content=content, json=json, data=data, **kwargs)

    async def head(self, url: str, **kwargs) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def trace(self, url: str, **kwargs) -> Response:
        return await self.request("TRACE", url, **kwargs)

    @staticmethod
    async def _sleep(delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    def _build_url_with_params(url: str, params: Dict[str, Union[str, int, float, None]]) -> str:
        """Build URL with query parameters."""
        if not params:
            return url
            
        parsed = urlparse(url)
        # Parse existing query parameters only if needed
        if parsed.query:
            existing_params = parse_qs(parsed.query, keep_blank_values=True)
            # Convert to simple dict (take first value from each list)
            existing_dict = {k: v[0] if v else "" for k, v in existing_params.items()}
        else:
            existing_dict = {}
        
        # Update with new params (filter out None values)
        new_params = {k: str(v) for k, v in params.items() if v is not None}
        if not new_params:
            return url
            
        existing_dict.update(new_params)
        # Build new query string
        query_string = urlencode(existing_dict)
        # Reconstruct URL
        new_parsed = parsed._replace(query=query_string)
        return urlunparse(new_parsed)

    def _has_header(self, headers: Dict[str, str], header_name: str) -> bool:
        """Fast case-insensitive header lookup using cache."""
        headers_id = id(headers)
        if headers_id not in self._header_cache:
            self._header_cache[headers_id] = {k.lower(): k for k in headers}
        return header_name in self._header_cache[headers_id]
    
    def _inject_cookies(self, headers: Dict[str, str], url: str) -> Dict[str, str]:
        if not headers:
            hdrs = {}
        else:
            hdrs = headers if isinstance(headers, dict) else dict(headers)
        
        cookie_hdr = self.cookies.get_cookie_header(url) if self.cookies else None
        if cookie_hdr and not self._has_header(hdrs, "cookie"):
            hdrs["Cookie"] = cookie_hdr
        return hdrs

    async def close(self) -> None:
        await self.pool.close()

    async def __aenter__(self) -> "Client":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
    
    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        # Try to call close() - if it's sync (wrapped), it will work directly
        # If it's async, it will return a coroutine
        result = self.close()
        
        # Check if result is a coroutine
        if asyncio.iscoroutine(result):
            # Still async, need to run in loop
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If loop is running, we can't use run_until_complete
                    # Create a task instead
                    task = asyncio.create_task(result)
                    # This is not ideal, but we'll let it run in background
                    return
                else:
                    loop.run_until_complete(result)
            except RuntimeError:
                # No event loop, create one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(result)
                loop.close()
        # If result is None or not a coroutine, it's already sync and done


__all__ = ["Client"]
