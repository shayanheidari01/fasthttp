import asyncio
import json as _json_module
import logging
import inspect
import ssl
import time
from typing import Any, Dict, List, Optional, Union, Awaitable, TypeVar, Tuple, Callable, Sequence
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qs

from ._version import __version__
from .pool import ConnectionPool
from .request import Request
from .response import Response
from .retry import RetryPolicy
from .logging import get_logger
from .cookies import CookieJar
from .errors import RequestError, HTTP2NotAvailable
from .timeouts import Timeout
from .websocket import WebSocket
from .auth import AuthBase, coerce_auth
from .formdata import FilesType, MultipartEncoder

T = TypeVar("T")
HookFunc = Callable[[Response], Union[Optional[Response], Awaitable[Optional[Response]]]]
HookValue = Union[HookFunc, Sequence[HookFunc]]
HooksInput = Dict[str, HookValue]
HooksMap = Dict[str, List[HookFunc]]


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
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        hooks: Optional[HooksInput] = None,
        http2: bool = False,
    ) -> None:
        self.base_url = base_url
        self.pool = pool or ConnectionPool()
        self.timeout = timeout
        self.retry = retry or RetryPolicy(max_attempts=1)
        self.logger = logger or get_logger()
        self.cookies = cookies or CookieJar()
        self.user_agent = user_agent or f"maxhttp/{__version__}"
        self.auth = coerce_auth(auth)
        self._hooks = self._normalize_hooks(hooks)
        self.http2 = http2
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
        files: Optional[FilesType] = None,
        params: Optional[Dict[str, Union[str, int, float, None]]] = None,
        timeout: Optional[float] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
        stream: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        auth: Optional[Union[Tuple[str, str], AuthBase]] = None,
        hooks: Optional[HooksInput] = None,
        http2: Optional[bool] = None,
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
            if any(item is not None for item in (content, form_data, files)):
                raise ValueError("Cannot specify 'content', 'data', or 'files' together with 'json'")
            current_content = _json_module.dumps(json_data).encode("utf-8")
            current_headers = headers or {}
            if "content-type" not in {k.lower() for k in current_headers}:
                current_headers["Content-Type"] = "application/json"
        elif files is not None:
            if content is not None:
                raise ValueError("Cannot specify both 'content' and 'files'")
            encoder = MultipartEncoder(fields=form_data, files=files)
            current_content = encoder.iter_bytes()
            current_headers = headers or {}
            if "content-type" not in {k.lower() for k in current_headers}:
                current_headers["Content-Type"] = encoder.content_type
            if "content-length" in {k.lower() for k in current_headers}:
                # Remove Content-Length because body is streamed
                current_headers = {k: v for k, v in current_headers.items() if k.lower() != "content-length"}
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
        auth_handler = coerce_auth(auth) if auth is not None else self.auth
        hooks_map = self._merge_hooks(hooks)

        def _remaining_total(timeout_cfg: Timeout) -> Optional[float]:
            total = timeout_cfg.total
            if total is None:
                return None
            elapsed = time.time() - start_time
            remaining = total - elapsed
            return max(0.0, remaining)

        async def _run_with_total(awaitable: Awaitable[T], timeout_cfg: Timeout) -> T:
            remaining = _remaining_total(timeout_cfg)
            if remaining is None:
                return await awaitable
            if remaining <= 0:
                raise RequestError("Total timeout exceeded")
            try:
                return await asyncio.wait_for(awaitable, timeout=remaining)
            except asyncio.TimeoutError as exc:
                raise RequestError("Total timeout exceeded") from exc

        preferred_http2 = http2 if http2 is not None else self.http2
        preferred_http2 = preferred_http2 and current_url.startswith("https://")

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
            if auth_handler:
                await auth_handler.on_request(req)
            # Circuit breaker: short-circuit if host is currently open
            if self.retry.is_circuit_open(req.host):
                raise RequestError(f"Circuit open for host {req.host}")

            timeout_cfg = req.timeout
            conn = await _run_with_total(
                self.pool.acquire(
                    req.scheme,
                    req.host,
                    req.port,
                    timeout=timeout_cfg,
                    verify=verify,
                    ssl_context=ssl_context,
                    http2=preferred_http2,
                ),
                timeout_cfg,
            )
            attempts = 0
            delays = list(self.retry.iter_delays())
            request_start_time = time.time()
            while True:
                attempts += 1
                try:
                    resp = await _run_with_total(conn.send_request(req, stream=stream), timeout_cfg)
                    # Set elapsed time
                    resp._set_elapsed(time.time() - request_start_time)
                    resp._history = response_history.copy()
                except HTTP2NotAvailable:
                    await conn.close()
                    if preferred_http2:
                        preferred_http2 = False
                        conn = await _run_with_total(
                            self.pool.acquire(
                                req.scheme,
                                req.host,
                                req.port,
                                timeout=timeout_cfg,
                                verify=verify,
                                ssl_context=ssl_context,
                                http2=False,
                            ),
                            timeout_cfg,
                        )
                        continue
                    raise
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
                        await _run_with_total(self._sleep(delay), timeout_cfg)
                        conn = await _run_with_total(
                            self.pool.acquire(
                                req.scheme,
                                req.host,
                                req.port,
                                timeout=timeout_cfg,
                                verify=verify,
                                ssl_context=ssl_context,
                            ),
                            timeout_cfg,
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
                    conn = await _run_with_total(
                        self.pool.acquire(
                            req.scheme,
                            req.host,
                            req.port,
                            timeout=timeout_cfg,
                            verify=verify,
                            ssl_context=ssl_context,
                        ),
                        timeout_cfg,
                    )
                    continue

                # Success (or non-retryable status on final attempt): record success or failure
                if not self.retry.should_retry_status(resp.status_code):
                    self.retry.record_success(req.host)
                else:
                    self.retry.record_failure(req.host)
                break

            self.cookies.add_from_response(resp)

            if auth_handler:
                new_req = await auth_handler.on_response(req, resp)
                if new_req is not None:
                    response_history.append(resp)
                    await conn.close()
                    method = new_req.method
                    current_url = new_req.url
                    current_headers = dict(new_req.headers)
                    current_content = new_req.content
                    resolved_timeout = new_req.timeout
                    continue

            if getattr(conn, "is_http2", False):
                should_close = conn.closed
            else:
                connection_header = resp.headers.get("Connection", resp.headers.get("connection", "keep-alive")).lower()
                should_close = connection_header == "close" or conn.closed
            if stream:
                async def _release_conn():
                    if should_close:
                        await conn.close()
                    else:
                        await self.pool.release(conn)

                resp._release = _release_conn
                resp = await self._dispatch_hooks("response", hooks_map, resp)
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
            resp = await self._dispatch_hooks("response", hooks_map, resp)
            return resp

    def _merge_hooks(self, request_hooks: Optional[HooksInput]) -> HooksMap:
        hooks: HooksMap = {event: funcs.copy() for event, funcs in self._hooks.items()}
        if not request_hooks:
            return hooks
        request_map = self._normalize_hooks(request_hooks)
        for event, funcs in request_map.items():
            hooks.setdefault(event, []).extend(funcs)
        return hooks

    def _normalize_hooks(self, hooks_input: Optional[HooksInput]) -> HooksMap:
        hooks: HooksMap = {}
        if not hooks_input:
            return hooks

        def _coerce(value: HookValue) -> List[HookFunc]:
            if callable(value):
                return [value]  # type: ignore[return-value]
            if isinstance(value, (list, tuple)):
                result: List[HookFunc] = []
                for item in value:
                    if not callable(item):
                        raise TypeError("Hook entries must be callables")
                    result.append(item)
                return result
            raise TypeError("hooks must be callables or sequences of callables")

        for event, value in hooks_input.items():
            if value is None:
                continue
            coerced = _coerce(value)
            if not coerced:
                continue
            hooks.setdefault(event, []).extend(coerced)
        return hooks

    async def _dispatch_hooks(self, event: str, hooks_map: HooksMap, response: Response) -> Response:
        hook_funcs = hooks_map.get(event)
        if not hook_funcs:
            return response

        current = response
        for hook in hook_funcs:
            result = hook(current)
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, Response):
                current = result
            elif result is not None:
                raise TypeError("Hook functions must return None or Response instances")
        return current

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        files: Optional[FilesType] = None,
        **kwargs,
    ) -> Response:
        return await self.request(
            "POST",
            url,
            content=content,
            json=json,
            data=data,
            files=files,
            **kwargs,
        )

    async def put(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        files: Optional[FilesType] = None,
        **kwargs,
    ) -> Response:
        return await self.request(
            "PUT",
            url,
            content=content,
            json=json,
            data=data,
            files=files,
            **kwargs,
        )

    async def delete(self, url: str, **kwargs) -> Response:
        return await self.request("DELETE", url, **kwargs)

    async def patch(
        self,
        url: str,
        content: Optional[bytes] = None,
        json: Optional[Any] = None,
        data: Optional[Dict[str, Union[str, int, float, None]]] = None,
        files: Optional[FilesType] = None,
        **kwargs,
    ) -> Response:
        return await self.request(
            "PATCH",
            url,
            content=content,
            json=json,
            data=data,
            files=files,
            **kwargs,
        )

    async def head(self, url: str, **kwargs) -> Response:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> Response:
        return await self.request("OPTIONS", url, **kwargs)

    async def trace(self, url: str, **kwargs) -> Response:
        return await self.request("TRACE", url, **kwargs)

    async def websocket(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        subprotocols: Optional[Sequence[str]] = None,
        extensions: Optional[Sequence] = None,
        timeout: Optional[Union[Timeout, float, int]] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> WebSocket:
        """
        Establish a WebSocket connection using the client's defaults.

        :returns: WebSocket instance
        """
        target_url = self._build_websocket_url(url)
        timeout_source: Union[Timeout, float, int, None]
        timeout_source = timeout if timeout is not None else self.timeout
        timeout_cfg = Timeout.from_value(timeout_source)
        return await WebSocket.connect(
            target_url,
            headers=headers,
            subprotocols=subprotocols,
            extensions=extensions,
            timeout=timeout_cfg,
            verify=verify,
            ssl_context=ssl_context,
        )

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

    def _build_websocket_url(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme in ("ws", "wss"):
            return url
        if parsed.scheme in ("http", "https"):
            scheme = "wss" if parsed.scheme == "https" else "ws"
            return parsed._replace(scheme=scheme).geturl()
        if not parsed.scheme and self.base_url:
            base = urlparse(self.base_url)
            combined = urljoin(self.base_url, url)
            combined_parsed = urlparse(combined)
            scheme = "wss" if base.scheme == "https" else "ws"
            return combined_parsed._replace(scheme=scheme).geturl()
        raise ValueError(
            "WebSocket URL must be absolute or the client must be initialized with base_url"
        )

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
