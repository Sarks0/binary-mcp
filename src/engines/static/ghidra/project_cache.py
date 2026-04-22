"""
Project cache manager for Ghidra analysis results.
Handles persistent storage and retrieval of analysis data.

Caches are written as gzipped JSON (``.json.gz``). Legacy uncompressed
``.json`` caches are transparently read for backward compatibility; when a
legacy cache is loaded via :meth:`get_cached` it is *not* auto-migrated -- the
next :meth:`save_cached` call will produce a ``.json.gz`` file alongside it.

Alongside each cache a small ``.funcidx.json`` side-car is maintained mapping
function address → index into the ``functions`` list, enabling O(1) lookups
without reading the full multi-megabyte cache.
"""

import gzip
import hashlib
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class ProjectCache:
    """Manages caching of Ghidra analysis results."""

    def __init__(self, cache_dir: str | None = None):
        """
        Initialize project cache.

        Args:
            cache_dir: Directory for cache storage. Defaults to ~/.ghidra_mcp_cache
        """
        if cache_dir is None:
            self.cache_dir = Path.home() / ".ghidra_mcp_cache"
        else:
            self.cache_dir = Path(cache_dir)

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Project cache initialized: {self.cache_dir}")

    def _get_binary_hash(self, binary_path: str) -> str:
        """Calculate SHA256 hash of binary file."""
        sha256 = hashlib.sha256()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_cache_path_gz(self, binary_hash: str) -> Path:
        """Path for the gzipped cache (current format)."""
        return self.cache_dir / f"{binary_hash}.json.gz"

    def _get_cache_path_legacy(self, binary_hash: str) -> Path:
        """Path for uncompressed cache (legacy format, read-only)."""
        return self.cache_dir / f"{binary_hash}.json"

    def _resolve_cache_path(self, binary_hash: str) -> Path | None:
        """Return the existing cache path (gz preferred, then legacy), or None."""
        gz = self._get_cache_path_gz(binary_hash)
        if gz.exists():
            return gz
        legacy = self._get_cache_path_legacy(binary_hash)
        if legacy.exists():
            return legacy
        return None

    def _get_metadata_path(self, binary_hash: str) -> Path:
        return self.cache_dir / f"{binary_hash}.meta.json"

    def _get_funcidx_path(self, binary_hash: str) -> Path:
        return self.cache_dir / f"{binary_hash}.funcidx.json"

    def has_cached(self, binary_path: str) -> bool:
        """Check if analysis results are cached for a binary."""
        try:
            binary_hash = self._get_binary_hash(binary_path)
            return self._resolve_cache_path(binary_hash) is not None
        except Exception as e:
            logger.error(f"Error checking cache: {e}")
            return False

    def get_cached(self, binary_path: str) -> dict | None:
        """Retrieve cached analysis results (gz or legacy)."""
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._resolve_cache_path(binary_hash)

            if cache_path is None:
                logger.debug(f"No cache found for {binary_path}")
                return None

            if cache_path.suffix == ".gz":
                with gzip.open(cache_path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(cache_path, encoding="utf-8") as f:
                    data = json.load(f)

            logger.info(
                f"Cache hit for {binary_path} "
                f"(hash: {binary_hash[:8]}..., fmt: {cache_path.suffix})"
            )
            return data

        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def get_cache_path(self, binary_path: str) -> Path | None:
        """
        Return the on-disk path for a binary's cache, or None if not cached.

        Callers (e.g. resumable analysis) need the path to hand to Ghidra
        without paying the cost of loading the JSON.
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            return self._resolve_cache_path(binary_hash)
        except Exception as e:
            logger.error(f"Error resolving cache path: {e}")
            return None

    def _build_function_index(self, data: dict) -> dict:
        """Build {address: index} map from cached context's functions list."""
        return {
            func.get("address"): idx
            for idx, func in enumerate(data.get("functions", []))
            if func.get("address")
        }

    def save_cached(self, binary_path: str, data: dict) -> bool:
        """Save analysis results to cache (gzipped) and write function index."""
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._get_cache_path_gz(binary_hash)
            metadata_path = self._get_metadata_path(binary_hash)
            funcidx_path = self._get_funcidx_path(binary_hash)
            legacy_path = self._get_cache_path_legacy(binary_hash)

            # Save gzipped analysis data
            with gzip.open(cache_path, "wt", encoding="utf-8") as f:
                json.dump(data, f)

            # Drop legacy uncompressed cache if present (we now have a fresh .gz)
            if legacy_path.exists():
                try:
                    legacy_path.unlink()
                    logger.debug(f"Removed legacy uncompressed cache: {legacy_path}")
                except OSError as e:
                    logger.warning(f"Could not remove legacy cache: {e}")

            # Build and persist function address index for O(1) lookups
            func_index = self._build_function_index(data)
            with open(funcidx_path, "w", encoding="utf-8") as f:
                json.dump(func_index, f)

            # Save metadata
            metadata = {
                "binary_path": str(Path(binary_path).resolve()),
                "binary_name": Path(binary_path).name,
                "binary_hash": binary_hash,
                "cached_at": time.time(),
                "cache_version": "2.0",
                "cache_format": "gzip",
                "function_count": len(func_index),
            }

            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)

            logger.info(
                f"Saved cache for {binary_path} "
                f"(hash: {binary_hash[:8]}..., {len(func_index)} functions indexed)"
            )
            return True

        except Exception as e:
            logger.error(f"Error saving cache: {e}")
            return False

    def get_function_by_address(
        self, binary_path: str, address: str
    ) -> dict | None:
        """
        Fast lookup of a single function by address using the side-car index.

        Falls back to scanning the full cache if the index is missing (e.g. a
        legacy cache that was never re-saved under the v2.0 format).
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            funcidx_path = self._get_funcidx_path(binary_hash)

            if funcidx_path.exists():
                with open(funcidx_path, encoding="utf-8") as f:
                    index = json.load(f)
                idx = index.get(address)
                if idx is None:
                    return None
                # We still need the full cache to get the function body -- but
                # we now know it exists without scanning.
                data = self.get_cached(binary_path)
                if data is None:
                    return None
                functions = data.get("functions", [])
                if 0 <= idx < len(functions):
                    return functions[idx]
                return None

            # No index -- legacy fallback: linear scan
            data = self.get_cached(binary_path)
            if data is None:
                return None
            for func in data.get("functions", []):
                if func.get("address") == address:
                    return func
            return None

        except Exception as e:
            logger.error(f"Error looking up function by address: {e}")
            return None

    def invalidate(self, binary_path: str) -> bool:
        """Invalidate cached results for a binary (all formats + sidecars)."""
        try:
            binary_hash = self._get_binary_hash(binary_path)
            paths = [
                self._get_cache_path_gz(binary_hash),
                self._get_cache_path_legacy(binary_hash),
                self._get_metadata_path(binary_hash),
                self._get_funcidx_path(binary_hash),
            ]

            for p in paths:
                if p.exists():
                    p.unlink()

            logger.info(f"Invalidated cache for {binary_path}")
            return True

        except Exception as e:
            logger.error(f"Error invalidating cache: {e}")
            return False

    def get_metadata(self, binary_path: str) -> dict | None:
        """Get cache metadata for a binary."""
        try:
            binary_hash = self._get_binary_hash(binary_path)
            metadata_path = self._get_metadata_path(binary_hash)

            if not metadata_path.exists():
                return None

            with open(metadata_path, encoding="utf-8") as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Error reading metadata: {e}")
            return None

    def list_cached(self) -> list[dict]:
        """List all cached binaries."""
        cached_binaries = []

        for meta_file in self.cache_dir.glob("*.meta.json"):
            try:
                with open(meta_file, encoding="utf-8") as f:
                    metadata = json.load(f)
                cached_binaries.append(metadata)
            except Exception as e:
                logger.error(f"Error reading {meta_file}: {e}")

        return sorted(cached_binaries, key=lambda x: x.get("cached_at", 0), reverse=True)

    def clear_all(self) -> int:
        """Clear all cached data (gz, legacy json, meta, funcidx)."""
        count = 0

        for pattern in ("*.json.gz", "*.json"):
            for cache_file in self.cache_dir.glob(pattern):
                try:
                    cache_file.unlink()
                    count += 1
                except Exception as e:
                    logger.error(f"Error deleting {cache_file}: {e}")

        logger.info(f"Cleared {count} cache entries")
        return count

    def get_cache_size(self) -> int:
        """Get total size of cache in bytes (all cache + sidecar files)."""
        total_size = 0

        for pattern in ("*.json.gz", "*.json"):
            for cache_file in self.cache_dir.glob(pattern):
                try:
                    total_size += cache_file.stat().st_size
                except Exception as e:
                    logger.error(f"Error getting size of {cache_file}: {e}")

        return total_size
