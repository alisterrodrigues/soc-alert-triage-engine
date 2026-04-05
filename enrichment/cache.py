"""Enrichment result cache — implemented in Phase 2."""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get(key: str, cache_dir: str) -> Optional[dict]:
    """Retrieve a cached enrichment result for the given key.

    Args:
        key: Cache key, typically a normalised IP address string.
        cache_dir: Directory where cache files are stored.

    Returns:
        Cached result dict if present and not expired, otherwise None.
    """
    raise NotImplementedError("Cache retrieval is implemented in Phase 2")


def set(key: str, value: dict, cache_dir: str, ttl_seconds: int = 3600) -> None:
    """Persist an enrichment result to the cache.

    Args:
        key: Cache key, typically a normalised IP address string.
        value: Enrichment result dict to cache.
        cache_dir: Directory where cache files are stored.
        ttl_seconds: Time-to-live for the cache entry in seconds.
    """
    raise NotImplementedError("Cache storage is implemented in Phase 2")


def is_expired(key: str, cache_dir: str, ttl_seconds: int = 3600) -> bool:
    """Check whether a cache entry has exceeded its TTL.

    Args:
        key: Cache key to check.
        cache_dir: Directory where cache files are stored.
        ttl_seconds: Maximum age in seconds before an entry is considered stale.

    Returns:
        True if the entry does not exist or has expired, False otherwise.
    """
    raise NotImplementedError("Cache expiry check is implemented in Phase 2")
