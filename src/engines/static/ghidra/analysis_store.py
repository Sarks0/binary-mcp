"""
Analysis storage manager for persistent analysis reports.
Stores complete analysis reports with UUIDs for retrieval across sessions.
"""

import json
import logging
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class AnalysisStore:
    """Manages persistent storage of analysis reports."""

    def __init__(self, store_dir: str | None = None):
        """
        Initialize analysis store.

        Args:
            store_dir: Directory for analysis storage. Defaults to ~/.ghidra_mcp_cache/analyses
        """
        if store_dir is None:
            self.store_dir = Path.home() / ".ghidra_mcp_cache" / "analyses"
        else:
            self.store_dir = Path(store_dir)

        self.store_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Analysis store initialized: {self.store_dir}")

    def _get_analysis_path(self, analysis_id: str) -> Path:
        """Get analysis content file path for an analysis ID."""
        return self.store_dir / f"{analysis_id}.analysis.json"

    def _get_metadata_path(self, analysis_id: str) -> Path:
        """Get metadata file path for an analysis ID."""
        return self.store_dir / f"{analysis_id}.meta.json"

    def save(
        self,
        name: str,
        content: str,
        binary_path: str | None = None,
        binary_hash: str | None = None,
        tags: list[str] | None = None,
        analysis_id: str | None = None
    ) -> str:
        """
        Save an analysis report.

        Args:
            name: Human-readable name for the analysis
            content: Full analysis content (markdown/text)
            binary_path: Path to analyzed binary (optional)
            binary_hash: SHA256 hash of binary (optional)
            tags: List of tags for categorization (optional)
            analysis_id: Use specific ID instead of generating new one (optional)

        Returns:
            Analysis ID (UUID)
        """
        try:
            # Generate or use provided analysis ID
            if analysis_id is None:
                analysis_id = str(uuid.uuid4())

            analysis_path = self._get_analysis_path(analysis_id)
            metadata_path = self._get_metadata_path(analysis_id)

            # Check if updating existing analysis
            is_update = analysis_path.exists()

            # Prepare analysis data
            analysis_data = {
                "analysis_id": analysis_id,
                "name": name,
                "content": content,
                "created_at": time.time() if not is_update else self._get_created_at(analysis_id),
                "updated_at": time.time(),
                "binary_path": binary_path,
                "binary_hash": binary_hash,
                "tags": tags or [],
                "content_length": len(content),
            }

            # Save analysis content
            with open(analysis_path, "w") as f:
                json.dump(analysis_data, f, indent=2)

            # Prepare metadata
            metadata = {
                "analysis_id": analysis_id,
                "name": name,
                "binary_path": binary_path,
                "binary_name": Path(binary_path).name if binary_path else "Unknown",
                "binary_hash": binary_hash,
                "created_at": analysis_data["created_at"],
                "updated_at": analysis_data["updated_at"],
                "tags": tags or [],
                "content_length": len(content),
                "size_bytes": analysis_path.stat().st_size if analysis_path.exists() else 0,
            }

            # Save metadata
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            action = "Updated" if is_update else "Saved"
            logger.info(f"{action} analysis: {name} (ID: {analysis_id[:8]}...)")
            return analysis_id

        except Exception as e:
            logger.error(f"Error saving analysis: {e}")
            raise RuntimeError(f"Failed to save analysis: {e}")

    def _get_created_at(self, analysis_id: str) -> float:
        """Get creation timestamp from existing analysis."""
        try:
            metadata = self.get_metadata(analysis_id)
            return metadata.get("created_at", time.time())
        except Exception:
            return time.time()

    def get(self, analysis_id: str) -> dict | None:
        """
        Retrieve an analysis report.

        Args:
            analysis_id: UUID of the analysis

        Returns:
            Analysis data dict, or None if not found
        """
        try:
            analysis_path = self._get_analysis_path(analysis_id)

            if not analysis_path.exists():
                logger.debug(f"Analysis not found: {analysis_id}")
                return None

            with open(analysis_path) as f:
                data = json.load(f)

            logger.info(f"Retrieved analysis: {data.get('name')} (ID: {analysis_id[:8]}...)")
            return data

        except Exception as e:
            logger.error(f"Error reading analysis: {e}")
            return None

    def get_metadata(self, analysis_id: str) -> dict | None:
        """
        Get metadata for an analysis.

        Args:
            analysis_id: UUID of the analysis

        Returns:
            Metadata dict, or None if not found
        """
        try:
            metadata_path = self._get_metadata_path(analysis_id)

            if not metadata_path.exists():
                return None

            with open(metadata_path) as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Error reading metadata: {e}")
            return None

    def list(
        self,
        tag_filter: str | None = None,
        binary_name_filter: str | None = None,
        limit: int | None = None
    ) -> list[dict]:
        """
        List all stored analyses.

        Args:
            tag_filter: Filter by tag (optional)
            binary_name_filter: Filter by binary name (regex supported, optional)
            limit: Maximum number of results (optional)

        Returns:
            List of metadata dicts sorted by update time (newest first)
        """
        analyses = []

        for meta_file in self.store_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)

                # Apply filters
                if tag_filter and tag_filter not in metadata.get("tags", []):
                    continue

                if binary_name_filter:
                    import re
                    pattern = re.compile(binary_name_filter, re.IGNORECASE)
                    if not pattern.search(metadata.get("binary_name", "")):
                        continue

                analyses.append(metadata)

            except Exception as e:
                logger.error(f"Error reading {meta_file}: {e}")

        # Sort by update time (newest first)
        analyses.sort(key=lambda x: x.get("updated_at", 0), reverse=True)

        # Apply limit
        if limit:
            analyses = analyses[:limit]

        return analyses

    def delete(self, analysis_id: str) -> bool:
        """
        Delete an analysis.

        Args:
            analysis_id: UUID of the analysis

        Returns:
            True if deleted successfully
        """
        try:
            analysis_path = self._get_analysis_path(analysis_id)
            metadata_path = self._get_metadata_path(analysis_id)

            deleted = False
            if analysis_path.exists():
                analysis_path.unlink()
                deleted = True

            if metadata_path.exists():
                metadata_path.unlink()
                deleted = True

            if deleted:
                logger.info(f"Deleted analysis: {analysis_id[:8]}...")
                return True
            else:
                logger.warning(f"Analysis not found: {analysis_id}")
                return False

        except Exception as e:
            logger.error(f"Error deleting analysis: {e}")
            return False

    def append(self, analysis_id: str, content: str) -> bool:
        """
        Append content to an existing analysis.

        Args:
            analysis_id: UUID of the analysis
            content: Content to append

        Returns:
            True if appended successfully
        """
        try:
            # Get existing analysis
            analysis = self.get(analysis_id)
            if not analysis:
                logger.error(f"Analysis not found: {analysis_id}")
                return False

            # Append content
            existing_content = analysis.get("content", "")
            new_content = existing_content + "\n\n" + content

            # Save updated analysis
            self.save(
                name=analysis.get("name", "Unknown"),
                content=new_content,
                binary_path=analysis.get("binary_path"),
                binary_hash=analysis.get("binary_hash"),
                tags=analysis.get("tags", []),
                analysis_id=analysis_id
            )

            logger.info(f"Appended to analysis: {analysis_id[:8]}...")
            return True

        except Exception as e:
            logger.error(f"Error appending to analysis: {e}")
            return False

    def clear_all(self) -> int:
        """
        Clear all stored analyses.

        Returns:
            Number of analyses removed
        """
        count = 0

        for analysis_file in self.store_dir.glob("*.json"):
            try:
                analysis_file.unlink()
                count += 1
            except Exception as e:
                logger.error(f"Error deleting {analysis_file}: {e}")

        logger.info(f"Cleared {count // 2} analyses")  # Divide by 2 (content + metadata)
        return count // 2

    def get_store_size(self) -> int:
        """
        Get total size of stored analyses in bytes.

        Returns:
            Total size in bytes
        """
        total_size = 0

        for analysis_file in self.store_dir.glob("*.json"):
            try:
                total_size += analysis_file.stat().st_size
            except Exception as e:
                logger.error(f"Error getting size of {analysis_file}: {e}")

        return total_size

    def get_stats(self) -> dict:
        """
        Get statistics about stored analyses.

        Returns:
            Dict with statistics
        """
        analyses = self.list()

        # Count by tags
        tag_counts = {}
        for analysis in analyses:
            for tag in analysis.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total_analyses": len(analyses),
            "total_size_bytes": self.get_store_size(),
            "total_size_mb": self.get_store_size() / 1024 / 1024,
            "tag_counts": tag_counts,
            "newest": analyses[0] if analyses else None,
            "oldest": analyses[-1] if analyses else None,
        }
