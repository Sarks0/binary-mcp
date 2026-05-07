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
import re
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Side-car suffixes that share the <hash>.<suffix> stem with a cache file.
# When auto-pruning legacy <hash>.json duplicates we must NOT touch these.
_SIDECAR_SUFFIXES = (".meta.json", ".funcidx.json", ".notes.json")


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
        pruned = self._prune_legacy_duplicates()
        if pruned:
            logger.info(
                f"Project cache initialized: {self.cache_dir} "
                f"(pruned {pruned} legacy .json duplicate(s))"
            )
        else:
            logger.info(f"Project cache initialized: {self.cache_dir}")

    def _prune_legacy_duplicates(self) -> int:
        """Delete legacy <hash>.json files that have a matching <hash>.json.gz.

        Pre-PR #113 caches were uncompressed JSON. After that PR every save
        writes ``.json.gz``; the legacy reader survives but no migration ever
        removes the now-redundant uncompressed copy. Over time these
        accumulate (every binary you've ever analyzed leaves an 11-130 KB
        file behind). On startup we drop any legacy .json that has a
        matching .json.gz -- the side-cars (.meta.json, .funcidx.json,
        .notes.json) are skipped because their stems include a sub-suffix.
        """
        pruned = 0
        for gz in self.cache_dir.glob("*.json.gz"):
            # gz.name == "<hash>.json.gz" -> stem of stem == "<hash>"
            binary_hash = Path(gz.stem).stem
            legacy = self.cache_dir / f"{binary_hash}.json"
            if not legacy.exists():
                continue
            # Defence in depth: never touch a side-car even if a hash
            # collision somehow produced one with this exact name.
            if any(legacy.name.endswith(s) for s in _SIDECAR_SUFFIXES):
                continue
            try:
                legacy.unlink()
                pruned += 1
            except OSError as e:
                logger.warning(f"Could not prune legacy cache {legacy}: {e}")
        return pruned

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

    def _get_notes_path(self, binary_hash: str) -> Path:
        """Path for the per-binary annotation side-car (Wave 1B).

        Survives :meth:`invalidate` so user-supplied notes are not lost
        when ``analyze_binary(force_reanalyze=True)`` or ``load_pdb``
        rebuilds the cache.
        """
        return self.cache_dir / f"{binary_hash}.notes.json"

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

    def _get_project_name(self, binary_path: str) -> str:
        """Mirror runner.py's project_name derivation from a binary path.

        Must stay in sync with ``GhidraRunner.analyze`` so cache cleanup
        targets the same ghidra_projects entries the runner created.
        """
        stem = Path(binary_path).stem
        name = re.sub(r'[^a-zA-Z0-9_.\-]', '_', stem)
        if name.startswith('-'):
            name = f"proj_{name}"
        return name

    def _ghidra_project_paths(self, project_name: str) -> list[Path]:
        """Return the .gpr / .lock / .rep paths for a project_name."""
        project_dir = self.cache_dir / "ghidra_projects"
        return [
            project_dir / f"{project_name}.gpr",
            project_dir / f"{project_name}.lock",
            project_dir / f"{project_name}.rep",
        ]

    def _drop_ghidra_project(self, project_name: str) -> int:
        """Remove a binary's Ghidra project artifacts.

        Returns the number of paths removed (0-3).
        """
        removed = 0
        for p in self._ghidra_project_paths(project_name):
            if not p.exists():
                continue
            try:
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=False)
                else:
                    p.unlink()
                removed += 1
            except OSError as e:
                logger.warning(f"Could not remove project artifact {p}: {e}")
        return removed

    def invalidate(self, binary_path: str, include_project: bool = False) -> bool:
        """Invalidate cached results for a binary (all formats + sidecars).

        The notes side-car (``<hash>.notes.json``) is intentionally
        preserved so that user-supplied annotations survive a
        ``force_reanalyze`` or ``load_pdb`` rebuild. Use :meth:`clear_all`
        for an explicit full wipe.

        Args:
            binary_path: Path to the binary whose cache should be dropped.
            include_project: Also remove the matching
                ``ghidra_projects/<name>.{gpr,lock,rep}`` artifacts. Use
                this only when you genuinely want to discard the Ghidra
                project state -- the next analyze on this binary will pay
                the full auto-analysis cost again (~10-15 min for big
                binaries).
        """
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

            if include_project:
                project_name = self._get_project_name(binary_path)
                self._drop_ghidra_project(project_name)

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

    def clear_all(self, include_projects: bool = False) -> int:
        """Clear all cached data (gz, legacy json, meta, funcidx, notes).

        Unlike :meth:`invalidate`, this is a destructive full wipe and
        also drops user-supplied annotation side-cars.

        Args:
            include_projects: Also remove the entire ``ghidra_projects/``
                directory. The next analyze on any binary will pay the
                full auto-analysis cost again. Off by default because
                Ghidra project state is the most expensive thing to
                rebuild.

        Returns:
            Number of files removed at the cache-dir top level. The
            ``ghidra_projects/`` directory removal (when requested) is
            counted as a single entry regardless of its size.
        """
        count = 0

        for pattern in ("*.json.gz", "*.json"):
            for cache_file in self.cache_dir.glob(pattern):
                try:
                    cache_file.unlink()
                    count += 1
                except Exception as e:
                    logger.error(f"Error deleting {cache_file}: {e}")

        if include_projects:
            project_dir = self.cache_dir / "ghidra_projects"
            if project_dir.exists():
                try:
                    shutil.rmtree(project_dir)
                    count += 1
                except Exception as e:
                    logger.error(f"Error deleting {project_dir}: {e}")

        logger.info(f"Cleared {count} cache entries")
        return count

    # --- Annotation side-car (Wave 1B) -------------------------------------

    def read_notes(self, binary_path: str) -> list[dict]:
        """Load the annotation side-car for a binary.

        Returns the ``notes`` list (possibly empty). Missing or
        malformed side-cars are logged and treated as "no notes".
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            notes_path = self._get_notes_path(binary_hash)
            if not notes_path.exists():
                return []
            with open(notes_path, encoding="utf-8") as f:
                payload = json.load(f)
            notes = payload.get("notes")
            if not isinstance(notes, list):
                logger.warning(
                    f"Notes side-car for {binary_path} has no 'notes' list; "
                    "treating as empty"
                )
                return []
            return notes
        except Exception as e:
            logger.error(f"Error reading notes side-car: {e}")
            return []

    def write_notes(self, binary_path: str, notes: list[dict]) -> bool:
        """Persist the annotation side-car for a binary.

        Writes ``{"version": 1, "notes": [...]}`` to
        ``<hash>.notes.json``. Returns ``True`` on success.
        """
        try:
            binary_hash = self._get_binary_hash(binary_path)
            notes_path = self._get_notes_path(binary_hash)
            payload = {"version": 1, "notes": notes}
            with open(notes_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Error writing notes side-car: {e}")
            return False

    @staticmethod
    def _function_key_for(func: dict, image_base_int: int | None) -> list[str]:
        """Return the candidate keys a function should match against.

        The first key is the symbolic name when the function carries a
        non-default name source. The RVA-based key
        (``"rva:0xHEX"``) is always included as a fallback so a single
        side-car entry can match either way -- e.g. when an analysis
        rerun upgrades a default name to a symbolic one (PDB load).
        """
        keys: list[str] = []
        name_source = func.get("name_source") or ""
        name = func.get("name") or ""
        if name and name_source and name_source != "DEFAULT":
            keys.append(name)
        if image_base_int is not None:
            try:
                addr_str = func.get("address") or ""
                addr_int = int(str(addr_str).lower().replace("0x", ""), 16)
                rva = addr_int - image_base_int
                if rva >= 0:
                    keys.append(f"rva:0x{rva:x}")
            except (ValueError, TypeError):
                pass
        return keys

    @staticmethod
    def _parse_image_base(metadata: dict) -> int | None:
        try:
            raw = metadata.get("image_base") or ""
            if not raw:
                return None
            return int(str(raw).lower().replace("0x", ""), 16)
        except (ValueError, TypeError):
            return None

    def apply_notes_overlay(self, binary_path: str, data: dict) -> dict:
        """Overlay user-supplied notes onto a freshly-built cache.

        Mutates ``data`` in place: each function entry whose name or
        RVA matches a side-car ``function_key`` gets a ``notes`` block
        attached with three sub-fields (``plate``, ``pre``, ``post``).
        ``plate`` is a flat string; ``pre`` / ``post`` are ``addr -> text``
        dicts. Ghidra-supplied ``plate_comment`` is left untouched
        because user notes live under the separate ``notes`` key --
        this guarantees a fresh Ghidra plate is never clobbered by an
        empty side-car entry.
        """
        try:
            notes = self.read_notes(binary_path)
            if not notes:
                return data
            functions = data.get("functions") or []
            if not functions:
                return data

            metadata = data.get("metadata") or {}
            image_base_int = self._parse_image_base(metadata)

            # Build a single-pass index from every key form a function
            # answers to (symbolic name plus RVA fallback) so each note
            # is delivered in O(1).
            key_to_func: dict[str, dict] = {}
            for func in functions:
                for key in self._function_key_for(func, image_base_int):
                    key_to_func.setdefault(key, func)

            for note in notes:
                if not isinstance(note, dict):
                    continue
                func_key = note.get("function_key")
                kind = note.get("kind")
                text = note.get("text")
                addr = note.get("addr")
                if not func_key or not kind or not text:
                    continue
                target = key_to_func.get(func_key)
                if target is None:
                    continue
                bucket = target.setdefault(
                    "notes", {"plate": "", "pre": {}, "post": {}}
                )
                # Defensive backfill in case a prior overlay produced a
                # legacy partial shape.
                bucket.setdefault("plate", "")
                bucket.setdefault("pre", {})
                bucket.setdefault("post", {})
                if kind == "plate":
                    bucket["plate"] = text
                elif kind in ("pre", "post") and addr:
                    bucket[kind][str(addr)] = text

            return data
        except Exception as e:
            # Overlay failures must never break analysis -- log and move
            # on with the unannotated cache.
            logger.error(f"Error applying notes overlay: {e}")
            return data

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
