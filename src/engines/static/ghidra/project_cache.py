"""
Project cache manager for Ghidra analysis results.
Handles persistent storage and retrieval of analysis data.
"""

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ProjectCache:
    """Manages caching of Ghidra analysis results."""

    def __init__(self, cache_dir: Optional[str] = None):
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
        """
        Calculate SHA256 hash of binary file.

        Args:
            binary_path: Path to binary file

        Returns:
            Hex string of SHA256 hash
        """
        sha256 = hashlib.sha256()
        with open(binary_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_cache_path(self, binary_hash: str) -> Path:
        """Get cache file path for a binary hash."""
        return self.cache_dir / f"{binary_hash}.json"

    def _get_metadata_path(self, binary_hash: str) -> Path:
        """Get metadata file path for a binary hash."""
        return self.cache_dir / f"{binary_hash}.meta.json"

    def has_cached(self, binary_path: str) -> bool:
        """
        Check if analysis results are cached for a binary.

        Args:
            binary_path: Path to binary file

        Returns:
            True if cache exists and is valid
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._get_cache_path(binary_hash)
            return cache_path.exists()
        except Exception as e:
            logger.error(f"Error checking cache: {e}")
            return False

    def get_cached(self, binary_path: str) -> Optional[dict]:
        """
        Retrieve cached analysis results.

        Args:
            binary_path: Path to binary file

        Returns:
            Analysis results dict, or None if not cached
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._get_cache_path(binary_hash)

            if not cache_path.exists():
                logger.debug(f"No cache found for {binary_path}")
                return None

            with open(cache_path, "r") as f:
                data = json.load(f)

            logger.info(f"Cache hit for {binary_path} (hash: {binary_hash[:8]}...)")
            return data

        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None

    def save_cached(self, binary_path: str, data: dict) -> bool:
        """
        Save analysis results to cache.

        Args:
            binary_path: Path to binary file
            data: Analysis results to cache

        Returns:
            True if saved successfully
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._get_cache_path(binary_hash)
            metadata_path = self._get_metadata_path(binary_hash)

            # Save analysis data
            with open(cache_path, "w") as f:
                json.dump(data, f, indent=2)

            # Save metadata
            metadata = {
                "binary_path": str(Path(binary_path).resolve()),
                "binary_name": Path(binary_path).name,
                "binary_hash": binary_hash,
                "cached_at": time.time(),
                "cache_version": "1.0",
            }

            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Saved cache for {binary_path} (hash: {binary_hash[:8]}...)")
            return True

        except Exception as e:
            logger.error(f"Error saving cache: {e}")
            return False

    def invalidate(self, binary_path: str) -> bool:
        """
        Invalidate cached results for a binary.

        Args:
            binary_path: Path to binary file

        Returns:
            True if invalidated successfully
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            cache_path = self._get_cache_path(binary_hash)
            metadata_path = self._get_metadata_path(binary_hash)

            if cache_path.exists():
                cache_path.unlink()
            if metadata_path.exists():
                metadata_path.unlink()

            logger.info(f"Invalidated cache for {binary_path}")
            return True

        except Exception as e:
            logger.error(f"Error invalidating cache: {e}")
            return False

    def get_metadata(self, binary_path: str) -> Optional[dict]:
        """
        Get cache metadata for a binary.

        Args:
            binary_path: Path to binary file

        Returns:
            Metadata dict, or None if not cached
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            metadata_path = self._get_metadata_path(binary_hash)

            if not metadata_path.exists():
                return None

            with open(metadata_path, "r") as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Error reading metadata: {e}")
            return None

    def list_cached(self) -> list[dict]:
        """
        List all cached binaries.

        Returns:
            List of metadata dicts for all cached binaries
        """
        cached_binaries = []

        for meta_file in self.cache_dir.glob("*.meta.json"):
            try:
                with open(meta_file, "r") as f:
                    metadata = json.load(f)
                cached_binaries.append(metadata)
            except Exception as e:
                logger.error(f"Error reading {meta_file}: {e}")

        return sorted(cached_binaries, key=lambda x: x.get("cached_at", 0), reverse=True)

    def clear_all(self) -> int:
        """
        Clear all cached data.

        Returns:
            Number of cache entries removed
        """
        count = 0

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
                count += 1
            except Exception as e:
                logger.error(f"Error deleting {cache_file}: {e}")

        logger.info(f"Cleared {count} cache entries")
        return count

    def get_cache_size(self) -> int:
        """
        Get total size of cache in bytes.

        Returns:
            Total cache size in bytes
        """
        total_size = 0

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                total_size += cache_file.stat().st_size
            except Exception as e:
                logger.error(f"Error getting size of {cache_file}: {e}")

        return total_size
