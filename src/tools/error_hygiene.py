"""
Model-facing error hygiene for MCP tool handlers.

Audit F-10: roughly 190 tool handlers across ``src/tools/`` returned
``f"Error: {e}"`` from a catch-all ``except`` block. Whatever the debugger,
the filesystem, or an external tool happened to put in the exception string
went straight into the model's context -- absolute host paths, the operator's
username (every output directory is rooted at ``Path.home()``), WinDbg/CDB
stdout, Pybag COM detail. From there it flows into generated reports, which
are frequently shared outside the machine that produced them.

The fix is not "hide everything". Two kinds of error text are worth keeping:

1. Validation messages raised by this project's own validators ("Invalid hash
   length: 33", "address must be hex", enum/range errors). The model needs
   those to correct its own call; replacing them with a reference ID would
   make the tools materially harder to drive. Those sites are left alone.
2. The curated envelope of a :class:`StructuredBaseError` -- error code,
   message, reason, and suggested actions. Those fields are composed
   field-by-field by this project (see ``src/utils/structured_errors.py``)
   and are the same kind of deliberate, actionable passthrough as
   ``GhidraAnalysisError.diagnostic`` in ``security.safe_error_message``.

What is *not* kept is ``StructuredError.debug_info``. That is the one field
that carries verbatim external-tool output: ``WinDbgBridgeError`` stores raw
CDB stdout under ``debug_info["output"]``, ``create_windbg_not_found_error``
stores the host search paths, and ``create_api_error`` stores the raw x64dbg
plugin message. It is dropped from the model-facing string and logged
internally against the reference ID instead.
"""

from __future__ import annotations

import logging
import uuid

from src.utils.security import safe_error_message
from src.utils.structured_errors import StructuredBaseError

logger = logging.getLogger(__name__)


def curated_structured_text(error: StructuredBaseError) -> str:
    """
    Render a structured error's curated fields, omitting ``debug_info``.

    Mirrors :meth:`StructuredError.to_user_message` line-for-line except that
    the trailing "Debug information" block is left out -- see the module
    docstring for why that block is the leaky one.

    Args:
        error: The structured error to render.

    Returns:
        Multi-line human-readable error text safe to hand to the model.
    """
    structured = error.structured_error

    lines = [f"Error [{structured.error.value}]: {structured.message}"]

    if structured.reason:
        lines.append(f"Reason: {structured.reason}")

    if structured.suggestions:
        lines.append("\nSuggested actions:")
        for index, suggestion in enumerate(structured.suggestions, 1):
            lines.append(f"  {index}. {suggestion}")

    return "\n".join(lines)


def safe_tool_error(operation: str, error: Exception) -> str:
    """
    Format any tool-handler exception for model consumption (audit F-10).

    Structured errors keep their curated envelope plus a reference ID; every
    other exception is routed through
    :func:`src.utils.security.safe_error_message`, which logs the detail
    internally, hands back a reference ID, and preserves the curated
    ``GhidraAnalysisError.diagnostic`` passthrough.

    Args:
        operation: Short description of what failed -- normally the tool
            name. Used as the user-facing message for unstructured errors.
        error: The caught exception.

    Returns:
        Safe error string.
    """
    if isinstance(error, StructuredBaseError):
        error_id = str(uuid.uuid4())[:8]
        # Log the whole structured error, debug_info included: the operator
        # reading the server log is on the host already, so nothing is
        # disclosed there that they cannot see anyway.
        logger.error(
            f"Error {error_id}: {operation or 'tool call'} failed: {error.to_json()}"
        )
        return f"{curated_structured_text(error)}\nReference ID: {error_id}"

    return safe_error_message(
        f"{operation} failed" if operation else "Tool call failed", error
    )
