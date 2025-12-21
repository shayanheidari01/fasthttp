import ssl
import asyncio
from typing import Dict, Optional
from urllib.parse import urljoin

from .async_pool import AsyncConnectionPool
from .request import Request
from .response import Response
from .retry import RetryPolicy
from .logging import get_logger
from .cookies import CookieJar
from .errors import RequestError


class AsyncClient:
    """
    Minimal async HTTP/1.1 client with connection pooling.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        pool: Optional[AsyncConnectionPool] = None,
        timeout: Optional[float] = None,
        retry: Optional[RetryPolicy] = None,
        logger=None,
        cookies: Optional[CookieJar] = None,
    ) -> None:
        self.base_url = base_url
        self.pool = pool or AsyncConnectionPool()
        self.timeout = timeout
        self.retry = retry or RetryPolicy(max_attempts=1)
        self.logger = logger or get_logger()
        self.cookies = cookies or CookieJar()

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
        timeout: Optional[float] = None,
        verify: bool = True,
        ssl_context: Optional[ssl.SSLContext] = None,
        stream: bool = False,
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> Response:
        current_url = urljoin(self.base_url, url) if self.base_url else url
        method = method.upper()
        resolved_timeout = timeout or self.timeout
        current_content = content
        current_headers = headers or {}
        redirect_codes = {301, 302, 303, 307, 308}
        redirects = 0

        while True:
            hdrs = self._inject_cookies(current_headers, current_url)
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
            while True:
                attempts += 1
                try:
                    resp = await conn.send_request(req, stream=stream)
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

                resp._arelease = _release_conn
                return resp

            if should_close:
                await conn.close()
            else:
                await self.pool.release(conn)

            if follow_redirects and not stream and resp.status_code in redirect_codes:
                if redirects >= max_redirects:
                    raise RequestError("Too many redirects")
                location = resp.headers.get("Location") or resp.headers.get("location")
                if not location:
                    return resp
                redirects += 1
                new_url = urljoin(current_url, location)
                if resp.status_code in {301, 302, 303}:
                    method = "GET"
                    current_content = None
                    current_headers = {k: v for k, v in current_headers.items() if k.lower() not in ("content-length", "transfer-encoding")}
                current_url = new_url
                continue

            return resp

    async def get(self, url: str, **kwargs) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, content: Optional[bytes] = None, **kwargs) -> Response:
        return await self.request("POST", url, content=content, **kwargs)

    @staticmethod
    async def _sleep(delay: float) -> None:
        if delay > 0:
            await asyncio.sleep(delay)

    def _inject_cookies(self, headers: Dict[str, str], url: str) -> Dict[str, str]:
        hdrs = dict(headers)
        cookie_hdr = self.cookies.get_cookie_header(url) if self.cookies else None
        if cookie_hdr and "cookie" not in {k.lower() for k in hdrs}:
            hdrs["Cookie"] = cookie_hdr
        return hdrs

    async def aclose(self) -> None:
        await self.pool.close()

    async def __aenter__(self) -> "AsyncClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
