"""Small HTTP redirect client with explicit credential-origin boundaries."""

from .client import (
    FetchResult,
    RedirectClient,
    RedirectError,
    RedirectHop,
    RedirectLimitError,
    RedirectLoopError,
    ResponseTooLargeError,
    UnsafeUrlError,
)

__version__ = "0.1.0"

__all__ = [
    "FetchResult",
    "RedirectClient",
    "RedirectError",
    "RedirectHop",
    "RedirectLimitError",
    "RedirectLoopError",
    "ResponseTooLargeError",
    "UnsafeUrlError",
    "__version__",
]
