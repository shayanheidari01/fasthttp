import json
from dataclasses import dataclass
import gzip
import codecs
try:
    import brotli  # type: ignore
    _BR_AVAILABLE = True
except Exception:  # pragma: no cover
    _BR_AVAILABLE = False
from typing import Any, AsyncIterator, Callable, Dict, Iterator, Optional

from .request import Request
from .errors import HTTPStatusError


@dataclass
class Response:
    status_code: int
    headers: Dict[str, str]
    content: Optional[bytes]
    reason: Optional[str] = None
    request: Optional[Request] = None
    connection: Any = None  # May be sync or async connection
    _iter: Optional[Iterator[bytes]] = None
    _aiter: Optional[AsyncIterator[bytes]] = None
    _release: Optional[Callable[[], Any]] = None
    _arelease: Optional[Callable[[], Any]] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    # Caches to avoid repeated decompression/decoding
    _decoded_cache: Optional[bytes] = None
    _text_cache: Optional[str] = None

    def _decoded_content(self) -> Optional[bytes]:
        if self.content is None:
            return None
        if self._decoded_cache is not None:
            return self._decoded_cache
        # Look up Content-Encoding case-insensitively (some servers or libs lowercase headers)
        encoding = ""
        for k, v in self.headers.items():
            if k.lower() == "content-encoding":
                encoding = v.lower()
                break
        if encoding == "gzip":
            try:
                out = gzip.decompress(self.content)
                self._decoded_cache = out
                return out
            except Exception:
                self._decoded_cache = self.content
                return self.content
        if encoding == "br" and _BR_AVAILABLE:
            try:
                out = brotli.decompress(self.content)
                self._decoded_cache = out
                return out
            except Exception:
                self._decoded_cache = self.content
                return self.content
        self._decoded_cache = self.content
        return self.content

    @property
    def encoding(self) -> str:
        # Detect charset from Content-Type header, default to utf-8
        content_type = ""
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                content_type = v
                break
        if content_type:
            lower_ct = content_type.lower()
            idx = lower_ct.find("charset=")
            if idx != -1:
                enc = content_type[idx + len("charset="):].split(";", 1)[0].strip().strip('"').strip("'")
                return enc or "utf-8"
        return "utf-8"

    def text(self, encoding: Optional[str] = None) -> str:
        # If caller provided encoding, don't use cached text (because it's encoding-specific)
        if encoding is None and self._text_cache is not None:
            return self._text_cache
        data = self._decoded_content()
        if data is None:
            return ""
        enc = encoding or self.encoding
        try:
            txt = data.decode(enc)
        except Exception:
            txt = data.decode("utf-8", errors="replace")
        if encoding is None:
            self._text_cache = txt
        return txt

    def json(self) -> Any:
        # Decode content (handle gzip/brotli and charset) via text(), then parse JSON
        return json.loads(self.text())

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 600:
            raise HTTPStatusError(self.status_code, f"HTTP {self.status_code}: {self.reason}", self)

    def iter_text(self) -> Iterator[str]:
        # For non-streaming responses: return single text
        if self._iter is None:
            if self.content is None:
                return iter([])  # type: ignore
            return iter([self.text()])

        def generator():
            decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
            try:
                for chunk in self._iter:
                    yield decoder.decode(chunk)
            finally:
                if self._release:
                    self._release()

        return generator()

    async def aiter_text(self) -> AsyncIterator[str]:
        if self._aiter is None:
            if self.content is None:
                return
            yield self.text()
            return

        decoder = codecs.getincrementaldecoder(self.encoding)(errors="replace")
        try:
            async for chunk in self._aiter:
                yield decoder.decode(chunk)
        finally:
            if self._arelease:
                await self._arelease()

    # Context manager support - sync and async
    def __enter__(self) -> "Response":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    async def __aenter__(self) -> "Response":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._arelease:
            await self._arelease()

    def __repr__(self) -> str:
        url = self.request.url if self.request else None
        return f"<Response [{self.status_code}] url={url!r} reason={self.reason!r}>"

    def iter_bytes(self) -> Iterator[bytes]:
        if self._iter is None:
            if self.content is None:
                return iter([])  # type: ignore
            return iter([self.content])

        def generator():
            try:
                for chunk in self._iter:
                    yield chunk
            finally:
                if self._release:
                    self._release()

        return generator()

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        if self._aiter is None:
            if self.content is None:
                return
            yield self.content
            return

        try:
            async for chunk in self._aiter:
                yield chunk
        finally:
            if self._arelease:
                await self._arelease()

    def close(self) -> None:
        if self._release:
            self._release()
