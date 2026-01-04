import base64
import hashlib
import secrets
from typing import Dict, Optional, Tuple, Union

from .errors import RequestError
from .request import Request
from .response import Response


class AuthBase:
    """Base class for authentication handlers."""

    async def on_request(self, request: Request) -> None:
        self._on_request(request)

    async def on_response(self, request: Request, response: Response) -> Optional[Request]:
        return self._on_response(request, response)

    def _on_request(self, request: Request) -> None:  # pragma: no cover - to be overridden
        return

    def _on_response(self, request: Request, response: Response) -> Optional[Request]:  # pragma: no cover - to be overridden
        return None


class BasicAuth(AuthBase):
    """Simple HTTP Basic authentication handler."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self._header_value = self._build_header()

    def _build_header(self) -> str:
        raw = f"{self.username}:{self.password}".encode("latin1")
        token = base64.b64encode(raw).decode("ascii")
        return f"Basic {token}"

    def _on_request(self, request: Request) -> None:
        if "Authorization" not in request.headers:
            request.headers["Authorization"] = self._header_value


class DigestAuth(AuthBase):
    """HTTP Digest authentication handler supporting MD5/SHA-256 and qop auth/auth-int."""

    SUPPORTED_ALGORITHMS = {
        "md5": hashlib.md5,
        "md5-sess": hashlib.md5,
        "sha-256": hashlib.sha256,
        "sha-256-sess": hashlib.sha256,
    }

    def __init__(self, username: str, password: str, *, algorithm: str = "MD5") -> None:
        self.username = username
        self.password = password
        self.algorithm = algorithm.lower()
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError("Unsupported digest algorithm")
        self._nonce_count = 0
        self._challenge: Optional[Dict[str, str]] = None
        self._last_nonce: Optional[str] = None

    async def on_request(self, request: Request) -> None:
        if self._challenge:
            self._apply_digest_header(request)

    async def on_response(self, request: Request, response: Response) -> Optional[Request]:
        if response.status_code != 401:
            return None
        header = response.headers.get("WWW-Authenticate") or response.headers.get("www-authenticate")
        if not header or "digest" not in header.lower():
            return None

        challenge = self._parse_challenge(header)
        if not challenge:
            return None

        nonce = challenge.get("nonce")
        if self._last_nonce == nonce and request.headers.get("Authorization", "").startswith("Digest"):
            return None

        self._challenge = challenge
        self._last_nonce = nonce
        new_headers = dict(request.headers)
        new_request = Request(
            method=request.method,
            url=request.url,
            headers=new_headers,
            content=request.content,
            timeout=request.timeout,
        )
        self._apply_digest_header(new_request)
        return new_request

    def _apply_digest_header(self, request: Request) -> None:
        if request._is_streaming_body():  # type: ignore[attr-defined]
            raise RequestError("Digest authentication does not support streaming bodies")
        if not self._challenge:
            return

        cnonce = secrets.token_hex(8)
        ha1 = self._build_ha1(cnonce)
        ha2 = self._build_ha2(request)
        nonce = self._challenge.get("nonce", "")
        qop = self._choose_qop()
        if nonce == "":
            raise RequestError("Digest authentication challenge missing nonce")

        if qop:
            self._nonce_count += 1
            nc_value = f"{self._nonce_count:08x}"
            response = self._hash(f"{ha1}:{nonce}:{nc_value}:{cnonce}:{qop}:{ha2}")
        else:
            response = self._hash(f"{ha1}:{nonce}:{ha2}")
            nc_value = ""

        parts = {
            "username": self.username,
            "realm": self._challenge.get("realm", ""),
            "nonce": nonce,
            "uri": request.target,
            "response": response,
            "algorithm": self._challenge.get("algorithm", "MD5"),
        }
        if qop:
            parts.update({"qop": qop, "nc": nc_value, "cnonce": cnonce})
        opaque = self._challenge.get("opaque")
        if opaque:
            parts["opaque"] = opaque

        header = "Digest " + ", ".join(
            [
                f"{k}={self._quote(v)}" if k not in ("qop", "nc") else f"{k}={v}"
                for k, v in parts.items()
                if v
            ]
        )
        request.headers["Authorization"] = header

    def _build_ha1(self, cnonce: Optional[str]) -> str:
        realm = self._challenge.get("realm", "") if self._challenge else ""
        ha1 = self._hash(f"{self.username}:{realm}:{self.password}")
        if self.algorithm.endswith("-sess") and self._challenge:
            nonce = self._challenge.get("nonce", "")
            if not nonce:
                raise RequestError("Digest authentication challenge missing nonce")
            if not cnonce:
                raise RequestError("Digest authentication requires client nonce for sess algorithm")
            ha1 = self._hash(f"{ha1}:{nonce}:{cnonce}")
        return ha1

    def _build_ha2(self, request: Request) -> str:
        method = request.method
        uri = request.target
        qop = self._choose_qop()
        if qop == "auth-int":
            body = request._content_bytes()
            body_hash = self._hash_bytes(body)
            return self._hash(f"{method}:{uri}:{body_hash}")
        return self._hash(f"{method}:{uri}")

    def _choose_qop(self) -> Optional[str]:
        if not self._challenge:
            return None
        qop = self._challenge.get("qop")
        if not qop:
            return None
        values = [v.strip() for v in qop.split(",") if v.strip()]
        if "auth" in values:
            return "auth"
        if "auth-int" in values:
            return "auth-int"
        return values[0] if values else None

    def _hash(self, data: str) -> str:
        hasher = self.SUPPORTED_ALGORITHMS[self.algorithm]
        return hasher(data.encode("utf-8")).hexdigest()

    def _hash_bytes(self, data: bytes) -> str:
        hasher = self.SUPPORTED_ALGORITHMS[self.algorithm]
        md = hasher()
        md.update(data)
        return md.hexdigest()

    @staticmethod
    def _quote(value: str) -> str:
        escaped = value.replace('"', '\\"')
        return f'"{escaped}"'

    @staticmethod
    def _parse_challenge(header: str) -> Dict[str, str]:
        challenge = {}
        if not header:
            return challenge
        try:
            # Remove "Digest " prefix if present
            header = header.strip()
            if header.lower().startswith("digest"):
                header = header[6:].strip()

            parts = []
            current = []
            in_quotes = False
            escape = False
            for ch in header:
                if ch == '"' and not escape:
                    in_quotes = not in_quotes
                if ch == "," and not in_quotes:
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                else:
                    current.append(ch)
                if ch == "\\" and not escape:
                    escape = True
                else:
                    escape = False
            tail = "".join(current).strip()
            if tail:
                parts.append(tail)

            for item in parts:
                if "=" not in item:
                    continue
                k, v = item.split("=", 1)
                k = k.strip()
                v = v.strip()
                if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                    v = v[1:-1]
                v = v.replace('\\"', '"')
                challenge[k] = v
        except Exception as exc:
            raise RequestError(f"Unable to parse digest challenge: {exc}") from exc
        return challenge


auth_types = Union[Tuple[str, str], AuthBase]


def coerce_auth(auth: Optional[auth_types]) -> Optional[AuthBase]:
    if auth is None:
        return None
    if isinstance(auth, tuple):
        username, password = auth
        return BasicAuth(username, password)
    if isinstance(auth, AuthBase):
        return auth
    raise TypeError("Invalid auth type provided")
