import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class Cookie:
    """Represents a single cookie with all its attributes."""
    name: str
    value: str
    domain: Optional[str] = None
    path: str = "/"
    expires: Optional[float] = None
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if cookie has expired."""
        if self.expires is None:
            return False
        return time.time() > self.expires

    def matches_domain(self, domain: str) -> bool:
        """Check if cookie matches the given domain."""
        if not self.domain:
            return False
        if self.domain == domain:
            return True
        if self.domain.startswith("."):
            # Subdomain matching: .example.com matches example.com and *.example.com
            return domain.endswith(self.domain) or domain == self.domain[1:]
        return False

    def matches_path(self, path: str) -> bool:
        """Check if cookie matches the given path."""
        return path.startswith(self.path)

    def matches(self, domain: str, path: str, secure: bool = False) -> bool:
        """Check if cookie matches domain, path, and security requirements."""
        if self.is_expired():
            return False
        if not self.matches_domain(domain):
            return False
        if not self.matches_path(path):
            return False
        if self.secure and not secure:
            return False
        return True


class CookieJar:
    """
    Full-featured cookie jar with support for path, expires, domain matching,
    and proper cookie parsing according to RFC 6265.
    """

    def __init__(self) -> None:
        self._cookies: List[Cookie] = []

    def set(
        self,
        name: str,
        value: str,
        domain: Optional[str] = None,
        path: str = "/",
        expires: Optional[float] = None,
        secure: bool = False,
        httponly: bool = False,
        samesite: Optional[str] = None,
    ) -> None:
        """Set a cookie. If a cookie with the same name, domain, and path exists, it will be replaced."""
        # Remove existing cookie with same name, domain, and path
        self._cookies = [
            c for c in self._cookies
            if not (c.name == name and c.domain == domain and c.path == path)
        ]
        # Add new cookie
        self._cookies.append(
            Cookie(
                name=name,
                value=value,
                domain=domain,
                path=path,
                expires=expires,
                secure=secure,
                httponly=httponly,
                samesite=samesite,
            )
        )

    def _parse_set_cookie(self, header_value: str) -> Optional[Cookie]:
        """Parse Set-Cookie header value into a Cookie object."""
        parts = [p.strip() for p in header_value.split(";")]
        if not parts:
            return None

        # First part is name=value
        name_value = parts[0]
        if "=" not in name_value:
            return None
        name, value = name_value.split("=", 1)
        name = name.strip()
        value = value.strip()

        # Parse attributes
        domain: Optional[str] = None
        path: str = "/"
        expires: Optional[float] = None
        secure: bool = False
        httponly: bool = False
        samesite: Optional[str] = None

        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower.startswith("domain="):
                domain = part.split("=", 1)[1].strip().strip('"').strip("'")
            elif part_lower.startswith("path="):
                path = part.split("=", 1)[1].strip().strip('"').strip("'")
            elif part_lower.startswith("expires="):
                expires_str = part.split("=", 1)[1].strip().strip('"').strip("'")
                try:
                    # Parse HTTP date format (RFC 1123)
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(expires_str)
                    expires = dt.timestamp() if dt else None
                except Exception:
                    pass
            elif part_lower.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1].strip())
                    expires = time.time() + max_age
                except Exception:
                    pass
            elif part_lower == "secure":
                secure = True
            elif part_lower == "httponly":
                httponly = True
            elif part_lower.startswith("samesite="):
                samesite = part.split("=", 1)[1].strip().strip('"').strip("'").lower()

        return Cookie(
            name=name,
            value=value,
            domain=domain,
            path=path,
            expires=expires,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

    def add_from_response(self, response) -> None:
        """Parse Set-Cookie headers from response and add cookies to jar."""
        request = getattr(response, "request", None)
        if not request:
            return

        url = getattr(request, "url", None)
        if not url:
            return

        parsed_url = urlparse(url)
        host = parsed_url.hostname
        path = parsed_url.path or "/"
        secure = parsed_url.scheme == "https"

        # Handle multiple Set-Cookie headers
        set_cookie_headers = []
        for key, value in response.headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(value)

        for header_value in set_cookie_headers:
            cookie = self._parse_set_cookie(header_value)
            if not cookie:
                continue

            # Set default domain if not provided
            if not cookie.domain:
                cookie.domain = host

            # Set default path if not provided
            if not cookie.path or cookie.path == "":
                cookie.path = path

            # Remove existing cookie with same name, domain, and path
            self._cookies = [
                c for c in self._cookies
                if not (
                    c.name == cookie.name
                    and c.domain == cookie.domain
                    and c.path == cookie.path
                )
            ]

            # Add new cookie
            self._cookies.append(cookie)

        # Clean up expired cookies
        self._cookies = [c for c in self._cookies if not c.is_expired()]

    def get_cookie_header(self, url: str) -> Optional[str]:
        """Get Cookie header value for the given URL."""
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        path = parsed_url.path or "/"
        secure = parsed_url.scheme == "https"

        if not host:
            return None

        # Find matching cookies
        matching_cookies: List[Tuple[int, Cookie]] = []
        for cookie in self._cookies:
            if cookie.matches(host, path, secure):
                # Sort by path length (longer paths first) and then by name
                path_length = len(cookie.path)
                matching_cookies.append((path_length, cookie))

        if not matching_cookies:
            return None

        # Sort by path length (descending) and name
        matching_cookies.sort(key=lambda x: (-x[0], x[1].name))

        # Build cookie header
        cookie_pairs = [f"{c.name}={c.value}" for _, c in matching_cookies]
        return "; ".join(cookie_pairs)

    def clear(self) -> None:
        """Clear all cookies."""
        self._cookies.clear()

    def remove(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
        """Remove cookies matching the given criteria."""
        self._cookies = [
            c for c in self._cookies
            if not (
                c.name == name
                and (domain is None or c.domain == domain)
                and (path is None or c.path == path)
            )
        ]
