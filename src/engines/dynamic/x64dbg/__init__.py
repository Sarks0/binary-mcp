"""
x64dbg debugger integration.

Provides dynamic analysis capabilities through x64dbg's native plugin API.

Components:
- Native C++ plugin (src/engines/dynamic/x64dbg/plugin/)
- HTTP API bridge
- Python client (bridge.py)
- MCP tool wrappers (commands.py)

Architecture:
    MCP Server (Python) <--HTTP--> x64dbg Plugin (C++) <--SDK--> x64dbg Core
"""

__all__ = []
