import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Iterable
from urllib.parse import urlparse
from functools import lru_cache


# Pre-compiled regex for better performance
_DATE_REGEX = re.compile(r'expires=([^;,\\s]+)', re.IGNORECASE)
_DOMAIN_REGEX = re.compile(r'domain=([^;,\\s]+)', re.IGNORECASE)
_PATH_REGEX = re.compile(r'path=([^;,\\s]+)', re.IGNORECASE)
_MAX_AGE_REGEX = re.compile(r'max-age=(\\d+)', re.IGNORECASE)
_SAMESITE_REGEX = re.compile(r'samesite=([^;,\\s]+)', re.IGNORECASE)

@lru_cache(maxsize=128)
def _parse_date(date_str: str) -> Optional[float]:
    """Parse HTTP date format with caching."""
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        return dt.timestamp() if dt else None
    except Exception:
        return None

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
    # Cache for domain matching to avoid repeated string operations
    _domain_pattern: Optional[str] = field(default=None, init=False, repr=False)
    _path_length: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        """Post-initialization to cache computed values."""
        self._path_length = len(self.path)
        if self.domain and self.domain.startswith("."):
            self._domain_pattern = self.domain[1:]  # Remove leading dot for pattern matching

    def is_expired(self) -> bool:
        """Check if cookie has expired."""
        if self.expires is None:
            return False
        return time.time() > self.expires

    def matches_domain(self, domain: str) -> bool:
        """Check if cookie matches given domain with optimized matching."""
        if not self.domain:
            return True  # Cookies without domain match any domain
        # Fast path: exact match
        if self.domain == domain:
            return True
        # Use cached pattern for subdomain matching
        if self._domain_pattern:
            return domain.endswith(self._domain_pattern) or domain == self._domain_pattern
        # Fallback to original logic
        if self.domain.startswith("."):
            return domain.endswith(self.domain) or domain == self.domain[1:]
        return False

    def matches_path(self, path: str) -> bool:
        """Check if cookie matches the given path."""
        return path.startswith(self.path)

    def matches(self, domain: str, path: str, secure: bool = False) -> bool:
        """Check if cookie matches domain, path, and security requirements with early exit."""
        # Early exit for expired cookies
        if self.expires is not None and time.time() > self.expires:
            return False
        # Early exit for domain mismatch
        if not self.matches_domain(domain):
            return False
        # Early exit for path mismatch using cached length
        if not path.startswith(self.path):
            return False
        # Early exit for secure mismatch
        if self.secure and not secure:
            return False
        return True


class CookieJar:
    """
    Full-featured cookie jar with support for path, expires, domain matching,
    and proper cookie parsing according to RFC 6265.

    Internally cookies are stored in a nested dictionary:
        domain -> path -> name -> Cookie
    This keeps lookups O(1) for the common host/path combinations.
    Match results are cached by (host, path, secure) keys for quick reuse.
    """

    def __init__(self) -> None:
        # domain -> path -> name -> Cookie
        self._store: Dict[str, Dict[str, Dict[str, Cookie]]] = {}
        self._total_cookies = 0
        # Cache for cookie header generation to avoid repeated processing
        self._header_cache: Dict[str, str] = {}
        # Cache for parsed URLs to avoid repeated parsing
        self._url_cache: Dict[str, Tuple[str, str, bool]] = {}
        # Cache for match results keyed by (host, path, secure)
        self._match_cache: Dict[Tuple[str, str, bool], List[Cookie]] = {}
        # Statistics for monitoring
        self._stats = {
            'cookies_added': 0,
            'cookies_removed': 0,
            'header_cache_hits': 0,
            'url_cache_hits': 0
        }

    def get_stats(self) -> Dict[str, int]:
        """Get cookie jar statistics for monitoring."""
        stats = self._stats.copy()
        stats['total_cookies'] = self._total_cookies
        stats['header_cache_size'] = len(self._header_cache)
        stats['url_cache_size'] = len(self._url_cache)
        stats['match_cache_size'] = len(self._match_cache)
        return stats

    @staticmethod
    def _normalize_domain(domain: Optional[str]) -> str:
        """
        Normalize domain key used for storage.
        Leading dots are stripped so `.example.com` and `example.com`
        share the same bucket, matching RFC behavior.
        """
        if not domain:
            return ""
        normalized = domain.lower()
        if normalized.startswith("."):
            normalized = normalized.lstrip(".")
        return normalized

    @staticmethod
    def _normalize_path(path: Optional[str]) -> str:
        """Normalize cookie paths and ensure they start with '/'."""
        if not path:
            return "/"
        if not path.startswith("/"):
            return f"/{path}"
        return path

    def _invalidate_caches(self) -> None:
        """Clear derived caches when the cookie jar mutates."""
        self._header_cache.clear()
        self._match_cache.clear()

    def _iter_all(self) -> Iterable[Tuple[str, str, Cookie]]:
        """Yield (domain_key, path_key, cookie) for every stored cookie."""
        for domain_key, paths in self._store.items():
            for path_key, names in paths.items():
                for cookie in names.values():
                    yield domain_key, path_key, cookie

    def _delete_cookie(self, domain_key: str, path_key: str, name: str) -> bool:
        """Remove a specific cookie entry, cleaning up empty buckets."""
        domain_bucket = self._store.get(domain_key)
        if not domain_bucket:
            return False
        path_bucket = domain_bucket.get(path_key)
        if not path_bucket or name not in path_bucket:
            return False
        del path_bucket[name]
        self._total_cookies -= 1
        if not path_bucket:
            domain_bucket.pop(path_key, None)
        if not domain_bucket:
            self._store.pop(domain_key, None)
        return True

    def _upsert_cookie(self, cookie: Cookie) -> None:
        """Insert or replace a cookie inside the nested store."""
        domain_key = self._normalize_domain(cookie.domain)
        path_key = self._normalize_path(cookie.path)
        domain_bucket = self._store.setdefault(domain_key, {})
        path_bucket = domain_bucket.setdefault(path_key, {})
        if cookie.name not in path_bucket:
            self._total_cookies += 1
        else:
            self._stats['cookies_removed'] += 1
        path_bucket[cookie.name] = cookie

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
        """Set or replace a cookie and invalidate caches."""
        self._invalidate_caches()
        self._stats['cookies_added'] += 1
        normalized_path = self._normalize_path(path)
        cookie = Cookie(
            name=name,
            value=value,
            domain=domain,
            path=normalized_path,
            expires=expires,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )
        self._upsert_cookie(cookie)

    def _parse_set_cookie(self, header_value: str) -> Optional[Cookie]:
        """Parse Set-Cookie header value into a Cookie object with optimized parsing."""
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

        # Parse attributes using pre-compiled regex for better performance
        domain: Optional[str] = None
        path: str = "/"
        expires: Optional[float] = None
        secure: bool = False
        httponly: bool = False
        samesite: Optional[str] = None

        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower.startswith("domain="):
                match = _DOMAIN_REGEX.search(part)
                if match:
                    domain = match.group(1).strip().strip('"').strip("'")
            elif part_lower.startswith("path="):
                match = _PATH_REGEX.search(part)
                if match:
                    path = match.group(1).strip().strip('"').strip("'")
            elif part_lower.startswith("expires="):
                match = _DATE_REGEX.search(part)
                if match:
                    expires = _parse_date(match.group(1).strip().strip('"').strip("'"))
            elif part_lower.startswith("max-age="):
                match = _MAX_AGE_REGEX.search(part)
                if match:
                    try:
                        max_age = int(match.group(1))
                        expires = time.time() + max_age
                    except ValueError:
                        pass
            elif part_lower == "secure":
                secure = True
            elif part_lower == "httponly":
                httponly = True
            elif part_lower.startswith("samesite="):
                match = _SAMESITE_REGEX.search(part)
                if match:
                    samesite = match.group(1).strip().strip('"').strip("'").lower()

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

        cache_invalidated = False

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

            self._invalidate_caches()
            self._stats['cookies_added'] += 1
            self._upsert_cookie(cookie)
            cache_invalidated = True

        # Clean up expired cookies
        expired_any = False
        for domain_key, path_key, stored_cookie in list(self._iter_all()):
            if stored_cookie.is_expired():
                if self._delete_cookie(domain_key, path_key, stored_cookie.name):
                    expired_any = True

        if cache_invalidated or expired_any:
            self._invalidate_caches()

    def get_cookie_header(self, url: str) -> Optional[str]:
        """Get Cookie header value for given URL with caching."""
        # Check URL cache first
        if url in self._url_cache:
            self._stats['url_cache_hits'] += 1
            host, path, secure = self._url_cache[url]
        else:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            path = parsed_url.path or "/"
            secure = parsed_url.scheme == "https"
            self._url_cache[url] = (host, path, secure)

        if not host:
            return None

        path = self._normalize_path(path)

        # Check header cache
        cache_key = f"{host}:{path}:{secure}"
        if cache_key in self._header_cache:
            self._stats['header_cache_hits'] += 1
            return self._header_cache[cache_key]

        matches = self._match_cookies(host, path, secure)
        if not matches:
            return None

        # Sort by path length (descending) and name for deterministic ordering
        matches.sort(key=lambda c: (-c._path_length, c.name))
        header_value = "; ".join(f"{c.name}={c.value}" for c in matches)
        
        # Cache the result
        self._header_cache[cache_key] = header_value
        return header_value

    def clear(self) -> None:
        """Clear all cookies and caches."""
        self._store.clear()
        self._total_cookies = 0
        self._header_cache.clear()
        self._url_cache.clear()
        self._match_cache.clear()

    def remove(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> None:
        """Remove cookies matching given criteria with optimized filtering."""
        self._invalidate_caches()
        removed_count = 0
        domain_keys: List[str]
        if domain is None:
            domain_keys = list(self._store.keys())
        else:
            domain_keys = [self._normalize_domain(domain)]
        for domain_key in domain_keys:
            domain_bucket = self._store.get(domain_key)
            if not domain_bucket:
                continue
            path_keys: List[str]
            if path is None:
                path_keys = list(domain_bucket.keys())
            else:
                path_keys = [self._normalize_path(path)]
            for path_key in path_keys:
                path_bucket = domain_bucket.get(path_key)
                if not path_bucket or name not in path_bucket:
                    continue
                del path_bucket[name]
                self._total_cookies -= 1
                removed_count += 1
                if not path_bucket:
                    domain_bucket.pop(path_key, None)
            if not domain_bucket:
                self._store.pop(domain_key, None)
        self._stats['cookies_removed'] += removed_count

    def _match_cookies(self, host: Optional[str], path: str, secure: bool) -> List[Cookie]:
        """Return cookies matching host/path/secure triple using cached results."""
        host_lower = (host or "").lower()
        cache_key = (host_lower, path, secure)
        if cache_key in self._match_cache:
            return list(self._match_cache[cache_key])

        matches: List[Cookie] = []
        buckets: List[Dict[str, Dict[str, Cookie]]] = []

        if host_lower:
            parts = host_lower.split(".")
            for i in range(len(parts)):
                candidate = ".".join(parts[i:])
                bucket = self._store.get(candidate)
                if bucket:
                    buckets.append(bucket)
            # Also consider the parent domain explicitly
            parent_bucket = self._store.get(host_lower)
            if parent_bucket and parent_bucket not in buckets:
                buckets.append(parent_bucket)
        default_bucket = self._store.get("")
        if default_bucket:
            buckets.append(default_bucket)

        for bucket in buckets:
            for path_key, names in bucket.items():
                if not path.startswith(path_key):
                    continue
                matches.extend(
                    cookie for cookie in names.values()
                    if cookie.matches(host_lower or host or "", path, secure)
                )

        self._match_cache[cache_key] = list(matches)
        return matches
