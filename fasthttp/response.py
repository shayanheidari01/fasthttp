import asyncio
import json
import zlib
import gzip
import codecs
import time
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

try:
    import brotli  # type: ignore
    _BR_AVAILABLE = True
except Exception:  # pragma: no cover
    _BR_AVAILABLE = False

from .request import Request
from .errors import HTTPStatusError, ResponseError


@dataclass
class Response:
    """
    HTTP response object with support for content decoding, streaming, and various convenience methods.
    """
    status_code: int
    headers: Dict[str, str]
    content: Optional[bytes]
    reason: Optional[str] = None
    request: Optional[Request] = None
    connection: Any = None  # Async connection
    _aiter: Optional[AsyncIterator[bytes]] = None
    _release: Optional[Callable[[], Any]] = None
    
    # Caches to avoid repeated decompression/decoding
    _decoded_cache: Optional[bytes] = field(default=None, init=False, repr=False)
    _text_cache: Optional[str] = field(default=None, init=False, repr=False)
    _json_cache: Optional[Any] = field(default=None, init=False, repr=False)
    _history: List["Response"] = field(default_factory=list, init=False, repr=False)
    _elapsed: Optional[float] = field(default=None, init=False, repr=False)
    _start_time: Optional[float] = field(default=None, init=False, repr=False)

    def _get_header(self, name: str, default: str = "") -> str:
        """
        Case-insensitive header lookup helper.
        Returns the header value or default if not found.
        """
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return default

    @property
    def ok(self) -> bool:
        """True if status code is in the 200-299 range."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """True if status code indicates a redirect (3xx)."""
        return 300 <= self.status_code < 400

    @property
    def is_permanent_redirect(self) -> bool:
        """True if status code is 301 or 308 (permanent redirect)."""
        return self.status_code in (301, 308)

    @property
    def url(self) -> Optional[str]:
        """The final URL after redirects."""
        return self.request.url if self.request else None

    @property
    def elapsed(self) -> float:
        """Time elapsed between request and response."""
        if self._elapsed is not None:
            return self._elapsed
        if self._start_time is not None:
            self._elapsed = time.time() - self._start_time
            return self._elapsed
        return 0.0

    @property
    def history(self) -> List["Response"]:
        """List of Response objects from redirect history."""
        return self._history

    def _set_start_time(self) -> None:
        """Set the start time for elapsed calculation."""
        if self._start_time is None:
            self._start_time = time.time()

    def _set_elapsed(self, elapsed: float) -> None:
        """Set elapsed time directly."""
        self._elapsed = elapsed

    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value."""
        return self._get_header("Content-Type") or None

    def _decoded_content(self) -> Optional[bytes]:
        """
        Decode content based on Content-Encoding header.
        Supports gzip, deflate, and brotli compression.
        Results are cached to avoid repeated decompression.
        """
        if self.content is None:
            return None
        if self._decoded_cache is not None:
            return self._decoded_cache
        
        encoding = self._get_header("Content-Encoding", "").lower().strip()
        
        # Handle multiple encodings (e.g., "gzip, deflate")
        encodings = [e.strip() for e in encoding.split(",") if e.strip()]
        
        data = self.content
        for enc in encodings:
            if enc == "gzip":
                try:
                    data = gzip.decompress(data)
                except Exception:
                    # If decompression fails, return original content
                    self._decoded_cache = self.content
                    return self.content
            elif enc == "deflate":
                try:
                    data = zlib.decompress(data)
                except Exception:
                    # Try with -zlib.MAX_WBITS for some servers
                    try:
                        data = zlib.decompress(data, -zlib.MAX_WBITS)
                    except Exception:
                        self._decoded_cache = self.content
                        return self.content
            elif enc == "br" and _BR_AVAILABLE:
                try:
                    data = brotli.decompress(data)
                except Exception:
                    self._decoded_cache = self.content
                    return self.content
        
        self._decoded_cache = data
        return data

    @property
    def encoding(self) -> str:
        """
        Detect charset from Content-Type header, default to utf-8.
        """
        content_type = self._get_header("Content-Type", "")
        if not content_type:
            return "utf-8"
        
        # Parse charset from Content-Type header
        # Format: "text/html; charset=utf-8" or "application/json;charset=iso-8859-1"
        lower_ct = content_type.lower()
        idx = lower_ct.find("charset=")
        if idx != -1:
            # Extract charset value
            charset_start = idx + len("charset=")
            charset_value = content_type[charset_start:].split(";", 1)[0].strip()
            # Remove quotes if present
            charset_value = charset_value.strip('"').strip("'").strip()
            if charset_value:
                return charset_value
        
        return "utf-8"

    def text(self, encoding: Optional[str] = None) -> str:
        """
        Decode response content as text.
        If encoding is provided, it overrides the detected encoding.
        Results are cached when using default encoding.
        """
        # If caller provided encoding, don't use cached text (because it's encoding-specific)
        if encoding is None and self._text_cache is not None:
            return self._text_cache
        
        data = self._decoded_content()
        if data is None:
            return ""
        
        enc = encoding or self.encoding
        try:
            txt = data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            # Fallback to utf-8 with error replacement
            try:
                txt = data.decode("utf-8", errors="replace")
            except Exception:
                # Last resort: latin-1 (never fails)
                txt = data.decode("latin-1", errors="replace")
        
        if encoding is None:
            self._text_cache = txt
        
        return txt

    def json(self) -> Any:
        """
        Decode response content as JSON.
        Results are cached to avoid repeated parsing.
        Raises ResponseError if content is not valid JSON.
        """
        if self._json_cache is not None:
            return self._json_cache
        
        text_content = self.text()
        if not text_content.strip():
            raise ResponseError("Response content is empty, cannot parse JSON")
        
        try:
            self._json_cache = json.loads(text_content)
            return self._json_cache
        except json.JSONDecodeError as e:
            raise ResponseError(f"Failed to parse JSON: {e}") from e

    @property
    def links(self) -> Dict[str, Dict[str, str]]:
        """
        Parse Link header and return a dictionary of links.
        Returns empty dict if no Link header is present.
        """
        link_header = self._get_header("Link", "")
        if not link_header:
            return {}
        
        links = {}
        # Parse Link header: <url>; rel="next", <url>; rel="prev"
        for link in link_header.split(","):
            link = link.strip()
            if not link.startswith("<"):
                continue
            
            # Extract URL
            url_end = link.find(">")
            if url_end == -1:
                continue
            
            url = link[1:url_end]
            params = link[url_end + 1:].strip()
            
            # Parse parameters
            link_info: Dict[str, str] = {"url": url}
            for param in params.split(";"):
                param = param.strip()
                if "=" in param:
                    key, value = param.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    link_info[key] = value
            
            # Use rel as key if present
            rel = link_info.get("rel", "alternate")
            links[rel] = link_info
        
        return links

    def raise_for_status(self) -> None:
        """
        Raise HTTPStatusError if status code indicates an error (4xx or 5xx).
        """
        if 400 <= self.status_code < 600:
            reason = self.reason or "Unknown error"
            raise HTTPStatusError(
                self.status_code,
                f"HTTP {self.status_code}: {reason}",
                self
            )

    async def iter_text(self, encoding: Optional[str] = None) -> AsyncIterator[str]:
        """
        Async iterator over response content as text chunks.
        For streaming responses, yields decoded text chunks.
        For non-streaming responses, yields the entire text content.
        """
        if self._aiter is None:
            # Non-streaming: yield entire content
            if self.content is None:
                return
            text = self.text(encoding=encoding)
            if text:
                yield text
            return

        # Streaming: decode chunks incrementally
        enc = encoding or self.encoding
        decoder = codecs.getincrementaldecoder(enc)(errors="replace")
        try:
            async for chunk in self._aiter:
                if chunk:
                    decoded = decoder.decode(chunk)
                    if decoded:
                        yield decoded
            # Flush any remaining decoded data
            final = decoder.decode(b"", final=True)
            if final:
                yield final
        finally:
            if self._release:
                await self._release()

    async def iter_bytes(self) -> AsyncIterator[bytes]:
        """
        Async iterator over response content as bytes chunks.
        For streaming responses, yields raw bytes chunks.
        For non-streaming responses, yields the entire content.
        """
        if self._aiter is None:
            # Non-streaming: yield entire content
            if self.content is None:
                return
            yield self.content
            return

        # Streaming: yield chunks as-is
        try:
            async for chunk in self._aiter:
                if chunk:
                    yield chunk
        finally:
            if self._release:
                await self._release()

    async def iter_lines(self, chunk_size: int = 8192) -> AsyncIterator[str]:
        """
        Async iterator over response content as lines.
        Lines are decoded using the detected encoding.
        """
        buffer = b""
        async for chunk in self.iter_bytes():
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line.endswith(b"\r"):
                    line = line[:-1]
                try:
                    decoded = line.decode(self.encoding)
                except Exception:
                    decoded = line.decode("utf-8", errors="replace")
                yield decoded
        
        # Yield remaining buffer as final line
        if buffer:
            try:
                decoded = buffer.decode(self.encoding)
            except Exception:
                decoded = buffer.decode("utf-8", errors="replace")
            yield decoded

    async def close(self) -> None:
        """
        Close the response and release associated resources.
        """
        if self._release:
            await self._release()
            self._release = None

    # Context manager support - async only
    async def __aenter__(self) -> "Response":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
    
    # Sync context manager support
    def __enter__(self) -> "Response":
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

    def __repr__(self) -> str:
        url = self.request.url if self.request else None
        return f"<Response [{self.status_code}] url={url!r} reason={self.reason!r}>"


