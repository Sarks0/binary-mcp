"""
Static analysis engines.

Currently supports:
- Ghidra (headless analysis)

Future support planned:
- IDA Pro
- Binary Ninja
- radare2
"""

from .ghidra.runner import GhidraRunner
from .ghidra.project_cache import ProjectCache

__all__ = ["GhidraRunner", "ProjectCache"]
