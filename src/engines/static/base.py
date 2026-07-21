"""
Base interface for static analysis engines.

All static analyzers should implement this interface for consistency.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class StaticAnalyzer(ABC):
    """Base class for static binary analysis engines."""

    @abstractmethod
    def analyze(
        self,
        binary_path: Path,
        output_path: Path,
        timeout: int = 600,
        **kwargs: Any
    ) -> dict[str, Any]:
        """
        Analyze a binary and return comprehensive analysis results.

        Args:
            binary_path: Path to the binary to analyze
            output_path: Path to write analysis results (JSON)
            timeout: Maximum time in seconds for analysis
            **kwargs: Engine-specific options

        Returns:
            Dictionary containing analysis metadata and results

        Raises:
            FileNotFoundError: If binary doesn't exist
            TimeoutError: If analysis exceeds timeout
            RuntimeError: If analysis fails
        """
        pass

    @abstractmethod
    def get_cache_key(self, binary_path: Path) -> str:
        """
        Generate a cache key for the binary.

        Typically SHA256 hash to detect file changes.

        Args:
            binary_path: Path to the binary

        Returns:
            Cache key string (e.g., SHA256 hex)
        """
        pass

    @abstractmethod
    def is_supported(self, binary_path: Path) -> bool:
        """
        Check if this analyzer supports the given binary format.

        Args:
            binary_path: Path to the binary

        Returns:
            True if analyzer can handle this binary format
        """
        pass

    @abstractmethod
    def diagnose(self) -> dict[str, Any]:
        """
        Run diagnostics on the analyzer installation.

        Returns:
            Dictionary with installation status and configuration
        """
        pass
