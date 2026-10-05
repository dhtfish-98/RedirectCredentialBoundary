"""Independent, intentionally narrow GET client for redirect credential policy."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import math
from typing import Mapping, Sequence
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DEFAULT_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "cookie", "cookie2", "referer"}
)


class RedirectError(Exception):
    """A request or redirect could not be completed within the configured policy."""


class UnsafeUrlError(RedirectError, ValueError):
    """A URL is outside the supported HTTP(S) URL subset."""


class RedirectLimitError(RedirectError):
    """The redirect chain exceeded its configured hop limit."""


class RedirectLoopError(RedirectError):
    """The redirect chain repeated a URL."""


class ResponseTooLargeError(RedirectError):
    """The final response exceeded its configured body limit."""


@dataclass(frozen=True)
class _Origin:
    scheme: str
    host: str
    port: int


@dataclass(frozen=True)
class RedirectHop:
    from_origin: str
    to_origin: str
    status: int
    stripped_header_names: tuple[str, ...]


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    history: tuple[RedirectHop, ...]


def _parse_url(value: str) -> tuple[SplitResult, _Origin, str]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise UnsafeUrlError("URL must be a nonempty string without surrounding whitespace")
    if any(ord(character) < 32 or character.isspace() or ord(character) == 127 for character in value):
        raise UnsafeUrlError("URL contains whitespace or a control character")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"}:
            raise UnsafeUrlError("only http and https URLs are supported")
        if parts.username is not None or parts.password is not None:
            raise UnsafeUrlError("credentials embedded in URLs are unsupported")
        host = parts.hostname
        if not host or "%" in host:
            raise UnsafeUrlError("URL needs an unambiguous host")
        port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
        if port < 1 or port > 65535:
            raise UnsafeUrlError("URL port is out of range")
        normalized_host = host.encode("idna").decode("ascii").lower()
        if any(ord(character) > 127 for character in parts.path + parts.query):
            raise UnsafeUrlError("URL path and query must be ASCII or percent-encoded")
    except (UnicodeError, ValueError) as error:
        if isinstance(error, UnsafeUrlError):
            raise
        raise UnsafeUrlError("URL authority is invalid") from None

    origin = _Origin(scheme, normalized_host, port)
    absolute_url = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    return parts, origin, absolute_url


def _configured_origin(value: str) -> _Origin:
    parts, origin, _ = _parse_url(value)
    if parts.path not in {"", "/"} or parts.query or parts.fragment:
        raise UnsafeUrlError("credential origin entries must contain only scheme, host, and port")
    return origin


def _request_target(parts: SplitResult) -> str:
    target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        raise UnsafeUrlError("request target contains a control character")
    return target


def _origin_label(origin: _Origin) -> str:
    host = f"[{origin.host}]" if ":" in origin.host else origin.host
    return f"{origin.scheme}://{host}:{origin.port}"


class RedirectClient:
    """Fetch GET URLs while retaining credentials only for approved origins.

    Same-origin redirects retain credentials. Each cross-origin exception needs
    an exact, directional source/destination origin pair. HTTPS-to-HTTP redirects
    always lose credentials, even when such a pair was configured.
    """

    def __init__(
        self,
        *,
        max_redirects: int = 5,
        timeout: float = 3.0,
        max_body_bytes: int = 1024 * 1024,
        credential_redirects: Sequence[tuple[str, str]] = (),
        credential_header_names: Sequence[str] = (),
    ) -> None:
        if isinstance(max_redirects, bool) or not isinstance(max_redirects, int) or max_redirects < 0:
            raise ValueError("max_redirects must be a nonnegative integer")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a nonnegative integer")
        self.max_redirects = max_redirects
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes
        pairs: set[tuple[_Origin, _Origin]] = set()
        for pair in credential_redirects:
            if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                raise ValueError("credential redirects must be source/destination origin pairs")
            pairs.add((_configured_origin(pair[0]), _configured_origin(pair[1])))
        self._credential_redirect_pairs = frozenset(pairs)
        names = set(_DEFAULT_CREDENTIAL_HEADERS)
        for name in credential_header_names:
            if not isinstance(name, str) or not name or any(not (char.isascii() and (char.isalnum() or char == "-")) for char in name):
                raise ValueError("credential header names must be HTTP token-like names")
            names.add(name.lower())
        self._credential_header_names = frozenset(names)

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> FetchResult:
        """Perform a bounded GET; return the final response and redirect decisions."""
        _, _, current_url = _parse_url(url)
        request_headers = self._validate_headers(headers or {})
        history: list[RedirectHop] = []
        visited: set[str] = set()

        while True:
            if current_url in visited:
                raise RedirectLoopError("redirect chain repeated a URL")
            visited.add(current_url)
            parts, current_origin, _ = _parse_url(current_url)
            status, received_headers, body, location = self._send_get(
                parts, current_origin, request_headers
            )
            if status not in _REDIRECT_STATUSES or location is None:
                return FetchResult(current_url, status, received_headers, body, tuple(history))

            if len(history) >= self.max_redirects:
                raise RedirectLimitError("redirect hop limit exceeded")
            if not location or location != location.strip() or any(
                ord(character) < 32 or ord(character) == 127 for character in location
            ):
                raise UnsafeUrlError("redirect Location is empty or malformed")
            target = urljoin(current_url, location)
            _, target_origin, target_url = _parse_url(target)
            should_strip = (
                target_origin != current_origin
                and (current_origin, target_origin) not in self._credential_redirect_pairs
            ) or (
                current_origin.scheme == "https" and target_origin.scheme == "http"
            )
            removed = tuple(
                sorted(name for name in request_headers if should_strip and name.lower() in self._credential_header_names)
            )
            if removed:
                request_headers = {
                    name: value for name, value in request_headers.items() if name not in removed
                }
            history.append(
                RedirectHop(
                    _origin_label(current_origin),
                    _origin_label(target_origin),
                    status,
                    removed,
                )
            )
            current_url = target_url

    @staticmethod
    def _validate_headers(headers: Mapping[str, str]) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not name or any(
                not (char.isascii() and (char.isalnum() or char == "-")) for char in name
            ):
                raise ValueError("header names must be HTTP token-like names")
            if name.lower() == "host":
                raise ValueError("Host is derived from the URL and cannot be overridden")
            if name.lower() == "proxy-authorization":
                raise ValueError("Proxy-Authorization is unsupported without proxy handling")
            if not isinstance(value, str) or any(
                ord(char) < 32 or ord(char) == 127 or ord(char) > 255 for char in value
            ):
                raise ValueError("header values must be Latin-1 without control characters")
            result[name] = value
        return result

    def _send_get(
        self, parts: SplitResult, origin: _Origin, headers: Mapping[str, str]
    ) -> tuple[int, tuple[tuple[str, str], ...], bytes, str | None]:
        connection_type = http.client.HTTPSConnection if origin.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(origin.host, origin.port, timeout=self.timeout)
        try:
            try:
                connection.request("GET", _request_target(parts), headers=dict(headers))
            except http.client.InvalidURL:
                raise UnsafeUrlError("request URL is invalid") from None
            response = connection.getresponse()
            status = response.status
            received_headers = tuple(response.getheaders())
            location = response.getheader("Location")
            if status in _REDIRECT_STATUSES and location is not None:
                body = b""
            else:
                body = response.read(self.max_body_bytes + 1)
                if len(body) > self.max_body_bytes:
                    raise ResponseTooLargeError("final response body exceeds limit")
            return status, received_headers, body, location
        finally:
            connection.close()
