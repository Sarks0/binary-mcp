"""GDB/MI engine for Linux dynamic analysis.

Exposes the MI output parser, the session transport that drives a
``gdb --interpreter=mi2`` subprocess, the console-command allowlist that bounds
what may be sent through ``-interpreter-exec console``, and the bridge that
implements the common ``Debugger`` interface on top of them. The MCP tool layer
lands in a later change; see the GDB/Linux debugging plan for the phasing.
"""

from src.engines.dynamic.gdb.allowlist import (
    MAX_COMMAND_LENGTH,
    allowed_commands,
    allowed_info_subcommands,
    validate_console_command,
)
from src.engines.dynamic.gdb.bridge import (
    MAX_READ_BYTES,
    GdbBridge,
    GdbBridgeError,
)
from src.engines.dynamic.gdb.mi_parser import (
    RESULT_CLASSES,
    MIParseError,
    MIRecord,
    RecordKind,
    parse_line,
    parse_lines,
    parse_value,
)
from src.engines.dynamic.gdb.mi_session import (
    DEFAULT_TIMEOUT,
    MIResponse,
    MISession,
    MISessionClosedError,
    MISessionError,
    MITimeoutError,
    find_gdb,
    quote_mi_argument,
)

__all__ = [
    "DEFAULT_TIMEOUT",
    "MAX_READ_BYTES",
    "GdbBridge",
    "GdbBridgeError",
    "MAX_COMMAND_LENGTH",
    "RESULT_CLASSES",
    "MIParseError",
    "MIRecord",
    "RecordKind",
    "parse_line",
    "parse_lines",
    "parse_value",
    "MIResponse",
    "MISession",
    "MISessionClosedError",
    "MISessionError",
    "MITimeoutError",
    "find_gdb",
    "quote_mi_argument",
    "allowed_commands",
    "allowed_info_subcommands",
    "validate_console_command",
]
