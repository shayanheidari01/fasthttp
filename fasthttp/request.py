from collections.abc import AsyncIterator as AsyncIterABC
from dataclasses import dataclass, field
from typing import Dict, Optional, Union, AsyncIterable
from urllib.parse import urlparse

from .timeouts import Timeout

try:
    import brotli  # type: ignore
    _BR_AVAILABLE = True
except Exception:  # pragma: no cover
    _BR_AVAILABLE = False

BodyType = Optional[
    Union[
        bytes,
        bytearray,
        memoryview,
        str,
        AsyncIterABC[bytes],
        AsyncIterable[bytes],
    ]
]


@dataclass
class Request:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    content: BodyType = None
    timeout: Timeout = field(default_factory=Timeout)
    _content_cache: Optional[bytes] = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.timeout = Timeout.from_value(self.timeout)
        parsed = urlparse(self.url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid URL: {self.url}")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.target = parsed.path or "/"
        if parsed.query:
            self.target += f"?{parsed.query}"
        self._normalize_headers()

    def _normalize_headers(self) -> None:
        lower_keys = {k.lower() for k in self.headers}
        if "host" not in lower_keys:
            host_hdr = self.host
            if self.port not in (80, 443):
                host_hdr = f"{host_hdr}:{self.port}"
            self.headers["Host"] = host_hdr
        if "accept-encoding" not in lower_keys:
            enc = "gzip, br" if _BR_AVAILABLE else "gzip"
            self.headers["Accept-Encoding"] = enc
        if self.content is not None and not self._is_streaming_body() and "content-length" not in lower_keys:
            length = len(self._content_bytes())
            self.headers["Content-Length"] = str(length)
        if self._is_streaming_body() and "content-length" not in lower_keys and "transfer-encoding" not in lower_keys:
            # Use chunked when length is unknown
            self.headers["Transfer-Encoding"] = "chunked"

    def _content_bytes(self) -> bytes:
        if self._content_cache is not None:
            return self._content_cache
        if self.content is None:
            self._content_cache = b""
            return self._content_cache
        if isinstance(self.content, (bytes, bytearray, memoryview)):
            self._content_cache = bytes(self.content)
            return self._content_cache
        if isinstance(self.content, str):
            self._content_cache = self.content.encode("utf-8")
            return self._content_cache
        raise TypeError("Unsupported content type")

    def _is_streaming_body(self) -> bool:
        if self.content is None:
            return False
        if isinstance(self.content, (bytes, bytearray, memoryview, str)):
            return False
        return isinstance(self.content, (AsyncIterABC, AsyncIterable))

    def iter_body(self) -> Optional[AsyncIterABC[bytes]]:
        if self.content is None or not self._is_streaming_body():
            return None
        if isinstance(self.content, (AsyncIterABC, AsyncIterable)):
            return self.content  # type: ignore[return-value]
        return None
