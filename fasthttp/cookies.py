from typing import Dict, Optional
from urllib.parse import urlparse


class CookieJar:
    """
    Minimal host-scoped cookie jar (no path/expires handling).
    """

    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, str]] = {}

    def set(self, name: str, value: str, domain: Optional[str] = None) -> None:
        if domain is None:
            return
        self._store.setdefault(domain, {})[name] = value

    def add_from_response(self, response) -> None:
        host = getattr(response.request, "host", None)
        header = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
        if not header or not host:
            return
        # Very small parser: "k=v; ..." -> k=v
        parts = header.split(";")
        if not parts:
            return
        kv = parts[0].strip()
        if "=" in kv:
            name, value = kv.split("=", 1)
            self.set(name.strip(), value.strip(), domain=host)

    def get_cookie_header(self, url: str) -> Optional[str]:
        host = urlparse(url).hostname
        if not host:
            return None
        jar = self._store.get(host)
        if not jar:
            return None
        return "; ".join(f"{k}={v}" for k, v in jar.items())
