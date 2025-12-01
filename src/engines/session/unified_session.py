"""
Unified session manager for static and dynamic binary analysis.

Provides automatic session management that:
- Works across both Ghidra (static) and x64dbg (dynamic) analysis
- Auto-starts sessions when first tool is called
- Correlates sessions by binary hash for conversation continuity
- Logs all tool calls for later retrieval and analysis reproduction
"""

import gzip
import hashlib
import json
import logging
import time
import uuid
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    """Type of analysis being performed."""
    STATIC = "static"
    DYNAMIC = "dynamic"
    MIXED = "mixed"


class UnifiedSessionManager:
    """
    Manages analysis sessions with automatic session handling.

    Key features:
    - Auto-session: Automatically starts a session on first tool call
    - Binary correlation: Finds related sessions by binary hash
    - Mixed analysis: Tracks both static and dynamic tool calls
    - Conversation continuity: Resumes recent sessions for same binary
    """

    # How long a session is considered "recent" for auto-resume (1 hour)
    SESSION_RESUME_WINDOW_SECONDS = 3600

    def __init__(self, store_dir: str | None = None):
        """
        Initialize unified session manager.

        Args:
            store_dir: Directory for session storage. Defaults to ~/.binary_mcp_sessions
        """
        if store_dir is None:
            self.store_dir = Path.home() / ".binary_mcp_sessions"
        else:
            self.store_dir = Path(store_dir)

        self.store_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Unified session manager initialized: {self.store_dir}")

        # Active session tracking
        self.active_session_id: str | None = None
        self.active_session_data: dict | None = None

        # Auto-session settings
        self.auto_session_enabled: bool = True
        self._current_binary_path: str | None = None
        self._current_binary_hash: str | None = None

    def _get_session_path(self, session_id: str) -> Path:
        """Get compressed session data file path."""
        return self.store_dir / f"{session_id}.session.json.gz"

    def _get_metadata_path(self, session_id: str) -> Path:
        """Get session metadata file path."""
        return self.store_dir / f"{session_id}.meta.json"

    def _compute_binary_hash(self, binary_path: str) -> str:
        """Compute SHA256 hash of binary file."""
        sha256 = hashlib.sha256()
        try:
            with open(binary_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.warning(f"Could not hash binary {binary_path}: {e}")
            # Fall back to path-based hash for dynamic analysis where file may not be local
            return hashlib.sha256(binary_path.encode()).hexdigest()

    def _find_recent_session_for_binary(self, binary_hash: str) -> str | None:
        """
        Find the most recent session for a binary within the resume window.

        Args:
            binary_hash: SHA256 hash of the binary

        Returns:
            Session ID if found, None otherwise
        """
        cutoff_time = time.time() - self.SESSION_RESUME_WINDOW_SECONDS

        best_session_id = None
        best_updated_at = 0

        for meta_file in self.store_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)

                # Check if same binary and recent enough
                if (metadata.get("binary_hash") == binary_hash and
                    metadata.get("updated_at", 0) > cutoff_time and
                    metadata.get("status") in ("active", "saved")):

                    updated_at = metadata.get("updated_at", 0)
                    if updated_at > best_updated_at:
                        best_updated_at = updated_at
                        best_session_id = metadata.get("session_id")

            except (json.JSONDecodeError, OSError) as e:
                logger.debug(f"Error reading {meta_file}: {e}")

        return best_session_id

    def ensure_session(
        self,
        binary_path: str | None = None,
        analysis_type: AnalysisType = AnalysisType.STATIC
    ) -> str:
        """
        Ensure a session is active, creating or resuming one if needed.

        This is the core auto-session method. Call it before logging tool calls.

        Args:
            binary_path: Path to binary being analyzed (optional for dynamic)
            analysis_type: Type of analysis (static, dynamic, or mixed)

        Returns:
            Active session ID
        """
        # If we already have an active session for this binary, use it
        if self.active_session_id and self.active_session_data:
            # Update analysis type if needed
            current_type = self.active_session_data.get("analysis_type", "static")
            if current_type != analysis_type.value and current_type != "mixed":
                self.active_session_data["analysis_type"] = "mixed"
            return self.active_session_id

        # Compute binary hash for correlation
        binary_hash = None
        if binary_path:
            binary_hash = self._compute_binary_hash(binary_path)
            self._current_binary_path = binary_path
            self._current_binary_hash = binary_hash

            # Try to find and resume a recent session for this binary
            if self.auto_session_enabled:
                recent_session_id = self._find_recent_session_for_binary(binary_hash)
                if recent_session_id:
                    if self._resume_session(recent_session_id):
                        logger.info(f"Auto-resumed session {recent_session_id[:8]}... for binary")
                        return recent_session_id

        # Create a new auto-session
        binary_name = Path(binary_path).name if binary_path else "unknown"
        session_name = f"Auto-session: {binary_name}"

        return self.start_session(
            binary_path=binary_path or "dynamic_analysis",
            name=session_name,
            analysis_type=analysis_type,
            tags=["auto-session", analysis_type.value]
        )

    def start_session(
        self,
        binary_path: str,
        name: str,
        analysis_type: AnalysisType = AnalysisType.STATIC,
        tags: list[str] | None = None
    ) -> str:
        """
        Start a new analysis session.

        Args:
            binary_path: Path to binary being analyzed
            name: Human-readable name for the session
            analysis_type: Type of analysis (static, dynamic, mixed)
            tags: Optional tags for categorization

        Returns:
            Session ID (UUID)
        """
        try:
            # Calculate binary hash
            binary_hash = self._compute_binary_hash(binary_path)

            # Create session
            session_id = str(uuid.uuid4())
            session_data = {
                "session_id": session_id,
                "name": name,
                "binary_path": binary_path,
                "binary_name": Path(binary_path).name,
                "binary_hash": binary_hash,
                "analysis_type": analysis_type.value,
                "tags": tags or [],
                "created_at": time.time(),
                "updated_at": time.time(),
                "tool_calls": [],
                "status": "active"
            }

            # Set as active session
            self.active_session_id = session_id
            self.active_session_data = session_data
            self._current_binary_path = binary_path
            self._current_binary_hash = binary_hash

            logger.info(f"Started {analysis_type.value} session: {name} (ID: {session_id[:8]}...)")
            return session_id

        except Exception as e:
            logger.error(f"Failed to start session: {e}")
            raise RuntimeError(f"Failed to start session: {e}")

    def _resume_session(self, session_id: str) -> bool:
        """
        Resume an existing session.

        Args:
            session_id: Session ID to resume

        Returns:
            True if resumed successfully
        """
        try:
            session_data = self._load_session_data(session_id)
            if not session_data:
                return False

            # Update status
            session_data["status"] = "active"
            session_data["updated_at"] = time.time()

            self.active_session_id = session_id
            self.active_session_data = session_data
            self._current_binary_path = session_data.get("binary_path")
            self._current_binary_hash = session_data.get("binary_hash")

            return True

        except Exception as e:
            logger.error(f"Failed to resume session {session_id}: {e}")
            return False

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        output: str,
        analysis_type: AnalysisType | None = None
    ) -> bool:
        """
        Log a tool call to the active session.

        Args:
            tool_name: Name of the tool that was called
            arguments: Tool arguments
            output: Tool output (formatted string)
            analysis_type: Type of analysis (for categorization)

        Returns:
            True if logged successfully
        """
        if not self.active_session_id or not self.active_session_data:
            logger.debug(f"No active session, skipping tool call log: {tool_name}")
            return False

        try:
            # Determine analysis type from tool name if not specified
            if analysis_type is None:
                if tool_name.startswith("x64dbg_"):
                    analysis_type = AnalysisType.DYNAMIC
                else:
                    analysis_type = AnalysisType.STATIC

            tool_call = {
                "timestamp": time.time(),
                "tool_name": tool_name,
                "arguments": self._sanitize_arguments(arguments),
                "output": output,
                "output_size": len(output),
                "analysis_type": analysis_type.value
            }

            self.active_session_data["tool_calls"].append(tool_call)
            self.active_session_data["updated_at"] = time.time()

            # Update session analysis type if mixed
            session_type = self.active_session_data.get("analysis_type", "static")
            if session_type != analysis_type.value and session_type != "mixed":
                self.active_session_data["analysis_type"] = "mixed"

            logger.debug(f"Logged tool call: {tool_name} ({len(output)} chars)")
            return True

        except Exception as e:
            logger.error(f"Failed to log tool call: {e}")
            return False

    def _sanitize_arguments(self, arguments: dict) -> dict:
        """Sanitize arguments for JSON serialization."""
        sanitized = {}
        for key, value in arguments.items():
            if isinstance(value, (str, int, float, bool, type(None))):
                sanitized[key] = value
            elif isinstance(value, (list, tuple)):
                sanitized[key] = [str(v) for v in value]
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_arguments(value)
            else:
                sanitized[key] = str(value)
        return sanitized

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

            # Calculate statistics
            tool_calls = session_data.get("tool_calls", [])
            tool_count = len(tool_calls)
            total_output_size = sum(call.get("output_size", 0) for call in tool_calls)

            # Count by analysis type
            static_count = sum(1 for c in tool_calls if c.get("analysis_type") == "static")
            dynamic_count = sum(1 for c in tool_calls if c.get("analysis_type") == "dynamic")

            # Create metadata (lightweight summary)
            metadata = {
                "session_id": session_id,
                "name": session_data.get("name"),
                "binary_path": session_data.get("binary_path"),
                "binary_name": session_data.get("binary_name"),
                "binary_hash": session_data.get("binary_hash"),
                "analysis_type": session_data.get("analysis_type"),
                "tags": session_data.get("tags", []),
                "created_at": session_data.get("created_at"),
                "updated_at": session_data.get("updated_at"),
                "status": session_data.get("status"),
                "tool_count": tool_count,
                "static_tool_count": static_count,
                "dynamic_tool_count": dynamic_count,
                "total_output_size": total_output_size,
                "compressed_size": session_path.stat().st_size if session_path.exists() else 0
            }

            # Save metadata
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)

            logger.info(
                f"Saved session: {session_data.get('name')} "
                f"(ID: {session_id[:8]}..., {tool_count} tools, "
                f"static: {static_count}, dynamic: {dynamic_count})"
            )
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
        # Check if it's the active session
        if session_id == self.active_session_id and self.active_session_data:
            return self.active_session_data

        # Load from disk
        return self._load_session_data(session_id)

    def get_metadata(self, session_id: str) -> dict | None:
        """Get lightweight metadata for a session."""
        try:
            metadata_path = self._get_metadata_path(session_id)
            if not metadata_path.exists():
                return None

            with open(metadata_path) as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return None

    def get_section(
        self,
        session_id: str,
        section_type: str,
        tool_filter: str | None = None,
        analysis_type_filter: str | None = None
    ) -> dict | None:
        """
        Get a specific section of session data.

        Args:
            session_id: UUID of the session
            section_type: "metadata", "tools", "summary", "static_tools", "dynamic_tools"
            tool_filter: Optional tool name filter
            analysis_type_filter: Filter by analysis type ("static" or "dynamic")

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
                tool_calls = session_data.get("tool_calls", [])
                return {
                    "session_id": session_data.get("session_id"),
                    "name": session_data.get("name"),
                    "binary_name": session_data.get("binary_name"),
                    "binary_hash": session_data.get("binary_hash"),
                    "analysis_type": session_data.get("analysis_type"),
                    "created_at": session_data.get("created_at"),
                    "tool_count": len(tool_calls),
                    "tools_used": list(set(call.get("tool_name") for call in tool_calls)),
                    "static_tools": list(set(
                        call.get("tool_name") for call in tool_calls
                        if call.get("analysis_type") == "static"
                    )),
                    "dynamic_tools": list(set(
                        call.get("tool_name") for call in tool_calls
                        if call.get("analysis_type") == "dynamic"
                    ))
                }

            if section_type in ("tools", "static_tools", "dynamic_tools"):
                tool_calls = session_data.get("tool_calls", [])

                # Filter by analysis type
                if section_type == "static_tools":
                    tool_calls = [c for c in tool_calls if c.get("analysis_type") == "static"]
                elif section_type == "dynamic_tools":
                    tool_calls = [c for c in tool_calls if c.get("analysis_type") == "dynamic"]
                elif analysis_type_filter:
                    tool_calls = [c for c in tool_calls if c.get("analysis_type") == analysis_type_filter]

                # Filter by tool name
                if tool_filter:
                    tool_calls = [c for c in tool_calls if c.get("tool_name") == tool_filter]

                return {
                    "session_id": session_id,
                    "tool_filter": tool_filter,
                    "analysis_type_filter": analysis_type_filter or section_type.replace("_tools", ""),
                    "tool_calls": tool_calls
                }

            return None

        except Exception as e:
            logger.error(f"Failed to get section: {e}")
            return None

    def find_sessions_for_binary(
        self,
        binary_path: str | None = None,
        binary_hash: str | None = None,
        limit: int = 10
    ) -> list[dict]:
        """
        Find all sessions related to a specific binary.

        Args:
            binary_path: Path to binary (will compute hash)
            binary_hash: Binary hash (if already known)
            limit: Maximum sessions to return

        Returns:
            List of session metadata sorted by update time
        """
        if binary_path and not binary_hash:
            binary_hash = self._compute_binary_hash(binary_path)

        if not binary_hash:
            return []

        sessions = []
        for meta_file in self.store_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)

                if metadata.get("binary_hash") == binary_hash:
                    sessions.append(metadata)

            except (json.JSONDecodeError, OSError) as e:
                logger.debug(f"Error reading {meta_file}: {e}")

        # Sort by update time (newest first)
        sessions.sort(key=lambda x: x.get("updated_at", 0), reverse=True)
        return sessions[:limit]

    def list_sessions(
        self,
        tag_filter: str | None = None,
        binary_name_filter: str | None = None,
        analysis_type_filter: str | None = None,
        limit: int | None = None
    ) -> list[dict]:
        """
        List all stored sessions.

        Args:
            tag_filter: Filter by tag
            binary_name_filter: Filter by binary name (regex supported)
            analysis_type_filter: Filter by analysis type ("static", "dynamic", "mixed")
            limit: Maximum number of results

        Returns:
            List of metadata dicts sorted by update time (newest first)
        """
        import re
        sessions = []

        for meta_file in self.store_dir.glob("*.meta.json"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)

                # Apply filters
                if tag_filter and tag_filter not in metadata.get("tags", []):
                    continue

                if binary_name_filter:
                    pattern = re.compile(binary_name_filter, re.IGNORECASE)
                    if not pattern.search(metadata.get("binary_name", "")):
                        continue

                if analysis_type_filter:
                    if metadata.get("analysis_type") != analysis_type_filter:
                        continue

                sessions.append(metadata)

            except Exception as e:
                logger.error(f"Error reading {meta_file}: {e}")

        # Sort by update time (newest first)
        sessions.sort(key=lambda x: x.get("updated_at", 0), reverse=True)

        if limit:
            sessions = sessions[:limit]

        return sessions

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
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
            self._current_binary_path = None
            self._current_binary_hash = None
            return True

        except Exception as e:
            logger.error(f"Failed to end session: {e}")
            return False

    def get_stats(self) -> dict:
        """Get statistics about stored sessions."""
        sessions = self.list_sessions()

        # Count by tags and analysis type
        tag_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {"static": 0, "dynamic": 0, "mixed": 0}
        total_size = 0

        for session in sessions:
            for tag in session.get("tags", []):
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
            total_size += session.get("compressed_size", 0)

            analysis_type = session.get("analysis_type", "static")
            if analysis_type in type_counts:
                type_counts[analysis_type] += 1

        return {
            "total_sessions": len(sessions),
            "total_size_bytes": total_size,
            "total_size_mb": total_size / 1024 / 1024,
            "tag_counts": tag_counts,
            "type_counts": type_counts,
            "active_session": self.active_session_id,
            "newest": sessions[0] if sessions else None,
            "oldest": sessions[-1] if sessions else None,
        }
