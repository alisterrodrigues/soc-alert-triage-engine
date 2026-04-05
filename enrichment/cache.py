import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """File-based JSON cache for enrichment results, keyed by module+IP.

    Each entry is stored as a separate JSON file named `{module}_{ip}.json`
    in the cache directory. Entries include a `fetched_at` Unix timestamp
    used to enforce TTL expiry.

    Args:
        cache_dir: Directory path for cache files. Created automatically.
        ttl_seconds: Seconds before a cache entry is considered stale.
    """

    def __init__(self, cache_dir: str, ttl_seconds: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, module: str, ip: str) -> Path:
        """Return the filesystem path for the cache file for (module, ip).

        Args:
            module: One of 'vt' or 'shodan'.
            ip: The IP address string.

        Returns:
            Path object for the cache file.
        """
        # Sanitize IP for filesystem safety (replace : and . with _)
        safe_ip = ip.replace(".", "_").replace(":", "_")
        return self.cache_dir / f"{module}_{safe_ip}.json"

    def get(self, module: str, ip: str) -> Optional[dict]:
        """Return cached data for (module, ip) if it exists and is not expired.

        Args:
            module: One of 'vt' or 'shodan'.
            ip: The IP address string used as the lookup key.

        Returns:
            The cached data dict, or None on cache miss or TTL expiry.
        """
        path = self._cache_path(module, ip)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                entry = json.load(f)
            fetched_at = entry.get("fetched_at", 0)
            if time.time() - fetched_at > self.ttl_seconds:
                logger.debug(f"Cache expired for {module}/{ip}")
                return None
            return entry.get("data")
        except Exception as e:
            logger.warning(f"Cache read error for {module}/{ip}: {e}")
            return None

    def set(self, module: str, ip: str, data: dict) -> None:
        """Write data to the cache for (module, ip).

        Args:
            module: One of 'vt' or 'shodan'.
            ip: The IP address string.
            data: The result dict to cache.
        """
        path = self._cache_path(module, ip)
        try:
            with open(path, "w") as f:
                json.dump({"fetched_at": time.time(), "data": data}, f)
        except Exception as e:
            logger.warning(f"Cache write error for {module}/{ip}: {e}")
