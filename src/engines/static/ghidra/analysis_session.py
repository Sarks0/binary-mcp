"""
Analysis session manager for incremental tool output storage.
Tracks all tool calls during an analysis session for later retrieval.
"""

import gzip
import json
import logging
import time
import uuid
from pathlib import Path

from src.utils.security import safe_regex_compile

logger = logging.getLogger(__name__)


class AnalysisSession:
    """Manages analysis sessions with incremental tool call logging."""

    def __init__(self, store_dir: str | None = None):
        """
        Initialize analysis session manager.

        Args:
            store_dir: Directory for session storage. Defaults to ~/.ghidra_mcp_cache/sessions
        """
        if store_dir is None:
            self.store_dir = Path.home() / ".ghidra_mcp_cache" / "sessions"
        else:
            self.store_dir = Path(store_dir)

        self.store_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Analysis session store initialized: {self.store_dir}")

        # Active session tracking
        self.active_session_id: str | None = None
        self.active_session_data: dict | None = None

    def _get_session_path(self, session_id: str) -> Path:
        """Get compressed session data file path."""
        return self.store_dir / f"{session_id}.session.json.gz"

    def _get_metadata_path(self, session_id: str) -> Path:
        """Get session metadata file path."""
        return self.store_dir / f"{session_id}.meta.json"

    def start_session(
        self,
        binary_path: str,
        name: str,
        tags: list[str] | None = None
    ) -> str:
        """
        Start a new analysis session.

        Args:
            binary_path: Path to binary being analyzed
            name: Human-readable name for the session
            tags: Optional tags for categorization

        Returns:
            Session ID (UUID)
        """
        try:
            # Calculate binary hash
            import hashlib
            sha256 = hashlib.sha256()
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            binary_hash = sha256.hexdigest()

            # Create session
            session_id = str(uuid.uuid4())
            session_data = {
                "session_id": session_id,
                "name": name,
                "binary_path": binary_path,
                "binary_name": Path(binary_path).name,
                "binary_hash": binary_hash,
                "tags": tags or [],
                "created_at": time.time(),
                "updated_at": time.time(),
                "tool_calls": [],
                "status": "active"
            }

            # Set as active session
            self.active_session_id = session_id
            self.active_session_data = session_data

            logger.info(f"Started session: {name} (ID: {session_id[:8]}...)")
            return session_id

        except Exception as e:
            logger.error(f"Failed to start session: {e}")
            raise RuntimeError(f"Failed to start session: {e}")

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        output: str
    ) -> bool:
        """
        Log a tool call to the active session.

        Args:
            tool_name: Name of the tool that was called
            arguments: Tool arguments
            output: Tool output (formatted string)

        Returns:
            True if logged successfully
        """
        if not self.active_session_id or not self.active_session_data:
            logger.debug(f"No active session, skipping tool call log: {tool_name}")
            return False

        try:
            tool_call = {
                "timestamp": time.time(),
                "tool_name": tool_name,
                "arguments": arguments,
                "output": output,
                "output_size": len(output)
            }

            self.active_session_data["tool_calls"].append(tool_call)
            self.active_session_data["updated_at"] = time.time()

            logger.debug(f"Logged tool call: {tool_name} ({len(output)} chars)")
            return True

        except Exception as e:
            logger.error(f"Failed to log tool call: {e}")
            return False

    def save_session(self, session_id: str | None = None) -> bool:
        """
        Save session to disk (compressed).

        Args:
            session_id: Session ID to save. If None, saves active session.

        Returns:
            True if saved successfully
        """
        try:
            # Determine which session to save
            if session_id is None:
                if not self.active_session_id or not self.active_session_data:
                    raise ValueError("No active session to save")
                session_id = self.active_session_id
                session_data = self.active_session_data
            else:
                # Load from disk if not active
                if session_id == self.active_session_id:
                    session_data = self.active_session_data
                else:
                    session_data = self._load_session_data(session_id)
                    if not session_data:
                        raise ValueError(f"Session not found: {session_id}")

            session_path = self._get_session_path(session_id)
            metadata_path = self._get_metadata_path(session_id)

            # Update status
            session_data["status"] = "saved"
            session_data["updated_at"] = time.time()

            # Save compressed session data
            with gzip.open(session_path, "wt", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2)

            # Calculate sizes
            tool_count = len(session_data.get("tool_calls", []))
            total_output_size = sum(
                call.get("output_size", 0)
                for call in session_data.get("tool_calls", [])
            )

            # Create metadata (lightweight summary)
            metadata = {
                "session_id": session_id,
                "name": session_data.get("name"),
                "binary_path": session_data.get("binary_path"),
                "binary_name": session_data.get("binary_name"),
                "binary_hash": session_data.get("binary_hash"),
                "tags": session_data.get("tags", []),
                "created_at": session_data.get("created_at"),
                "updated_at": session_data.get("updated_at"),
                "status": session_data.get("status"),
                "tool_count": tool_count,
                "total_output_size": total_output_size,
                "compressed_size": session_path.stat().st_size if session_path.exists() else 0
            }

            # Save metadata
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Saved session: {session_data.get('name')} (ID: {session_id[:8]}..., {tool_count} tools, {total_output_size / 1024:.1f} KB)")
            return True

        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False

    def _load_session_data(self, session_id: str) -> dict | None:
        """Load full session data from disk."""
        try:
            session_path = self._get_session_path(session_id)
            if not session_path.exists():
                return None

            with gzip.open(session_path, "rt", encoding="utf-8") as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Failed to load session data: {e}")
            return None

    def get_session(self, session_id: str) -> dict | None:
        """
        Retrieve a session's data.

        Args:
            session_id: UUID of the session

        Returns:
            Full session data dict, or None if not found
        """
        try:
            # Check if it's the active session
            if session_id == self.active_session_id and self.active_session_data:
                return self.active_session_data

            # Load from disk
            return self._load_session_data(session_id)

        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None

    def get_metadata(self, session_id: str) -> dict | None:
        """
        Get lightweight metadata for a session.

        Args:
            session_id: UUID of the session

        Returns:
            Metadata dict, or None if not found
        """
        try:
            metadata_path = self._get_metadata_path(session_id)
            if not metadata_path.exists():
                return None

            with open(metadata_path) as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return None

    def get_section(self, session_id: str, section_type: str, tool_filter: str | None = None) -> dict | None:
        """
        Get a specific section of session data (for chunked retrieval).

        Args:
            session_id: UUID of the session
            section_type: "metadata", "tools", or "summary"
            tool_filter: Optional tool name filter (e.g., "decompile_function")

        Returns:
            Section data dict
        """
        try:
            if section_type == "metadata":
                return self.get_metadata(session_id)

            # Load full session for other sections
            session_data = self.get_session(session_id)
            if not session_data:
                return None

            if section_type == "summary":
                return {
                    "session_id": session_data.get("session_id"),
                    "name": session_data.get("name"),
                    "binary_name": session_data.get("binary_name"),
                    "binary_hash": session_data.get("binary_hash"),
                    "created_at": session_data.get("created_at"),
                    "tool_count": len(session_data.get("tool_calls", [])),
                    "tools_used": list(set(
                        call.get("tool_name")
                        for call in session_data.get("tool_calls", [])
                    ))
                }

            if section_type == "tools":
                tool_calls = session_data.get("tool_calls", [])
                if tool_filter:
                    tool_calls = [
                        call for call in tool_calls
                        if call.get("tool_name") == tool_filter
                    ]
                return {
                    "session_id": session_id,
                    "tool_filter": tool_filter,
                    "tool_calls": tool_calls
                }

            return None

        except Exception as e:
            logger.error(f"Failed to get section: {e}")
            return None

    def list_sessions(
        self,
        tag_filter: str | None = None,
        binary_name_filter: str | None = None,
        limit: int | None = None
    ) -> list[dict]:
        """
        List all stored sessions.

        Args:
            tag_filter: Filter by tag (optional)
            binary_name_filter: Filter by binary name (regex supported, optional)
            limit: Maximum number of results (optional)

        Returns:
            List of metadata dicts sorted by update time (newest first)
        """
        sessions = []

        for meta_file in self.store_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)

                # Apply filters
                if tag_filter and tag_filter not in metadata.get("tags", []):
                    continue

                if binary_name_filter:
                    try:
                        pattern = safe_regex_compile(binary_name_filter, max_length=200)
                        if not pattern.search(metadata.get("binary_name", "")):
                            continue
                    except ValueError:
                        # Invalid regex pattern - skip this filter
                        logger.warning(f"Invalid binary_name_filter pattern: {binary_name_filter}")
                        continue

                sessions.append(metadata)

            except Exception as e:
                logger.error(f"Error reading {meta_file}: {e}")

        # Sort by update time (newest first)
        sessions.sort(key=lambda x: x.get("updated_at", 0), reverse=True)

        # Apply limit
        if limit:
            sessions = sessions[:limit]

        return sessions

    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: UUID of the session

        Returns:
            True if deleted successfully
        """
        try:
            session_path = self._get_session_path(session_id)
            metadata_path = self._get_metadata_path(session_id)

            deleted = False
            if session_path.exists():
                session_path.unlink()
                deleted = True

            if metadata_path.exists():
                metadata_path.unlink()
                deleted = True

            # Clear active session if deleting it
            if session_id == self.active_session_id:
                self.active_session_id = None
                self.active_session_data = None

            if deleted:
                logger.info(f"Deleted session: {session_id[:8]}...")
                return True
            else:
                logger.warning(f"Session not found: {session_id}")
                return False

        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False

    def end_session(self, save: bool = True) -> bool:
        """
        End the active session.

        Args:
            save: Whether to save before ending (default: True)

        Returns:
            True if ended successfully
        """
        if not self.active_session_id:
            logger.warning("No active session to end")
            return False

        try:
            if save:
                self.save_session()

            logger.info(f"Ended session: {self.active_session_id[:8]}...")
            self.active_session_id = None
            self.active_session_data = None
            return True

        except Exception as e:
            logger.error(f"Failed to end session: {e}")
            return False

    def get_stats(self) -> dict:
        """
        Get statistics about stored sessions.

        Returns:
            Dict with statistics
        """
        sessions = self.list_sessions()

        # Count by tags
        tag_counts = {}
        total_size = 0
        for session in sessions:
            for tag in session.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
            total_size += session.get("compressed_size", 0)

        return {
            "total_sessions": len(sessions),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / 1024 / 1024,
            "tag_counts": tag_counts,
            "active_session": self.active_session_id,
            "newest": sessions[0] if sessions else None,
            "oldest": sessions[-1] if sessions else None,
        }
