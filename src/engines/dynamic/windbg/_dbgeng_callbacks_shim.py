# ruff: noqa: N802
# DbgEng's IDebugEventCallbacks vtable dispatches by exact COM method name
# (CreateProcess, LoadModule, ...), so PascalCase here is mandatory.
"""
comtypes shim that exposes :class:`BinaryMcpEventCallbacks` to DbgEng as a
real COM object implementing IDebugEventCallbacks.

This module is Windows-only - importing it on non-Windows raises at
``import comtypes``. Callers (``event_callbacks.register_callbacks``)
guard the import with try/except.

Why a separate module: keeping the comtypes-dependent surface area in
one file means the rest of the bridge stays portable, mockable, and
testable on POSIX dev boxes / CI runners.

Reference:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugeventcallbacks
- IDebugEventCallbacks IID: {337be28b-5036-4d72-b6bf-c45fbb9f2eaa}
"""

from __future__ import annotations

import logging
from ctypes import HRESULT, c_uint, c_ulonglong, c_void_p, c_wchar_p
from typing import Any

import comtypes  # type: ignore[import-not-found]
from comtypes import (  # type: ignore[import-not-found]
    COMMETHOD,
    GUID,
    IUnknown,
)

logger = logging.getLogger(__name__)

# IID per MS Learn (IDebugEventCallbacks)
IID_IDebugEventCallbacks = GUID("{337be28b-5036-4d72-b6bf-c45fbb9f2eaa}")

# DEBUG_EVENT_* interest mask bits (we want everything we can get)
DEBUG_EVENT_BREAKPOINT = 0x00000001
DEBUG_EVENT_EXCEPTION = 0x00000002
DEBUG_EVENT_CREATE_THREAD = 0x00000004
DEBUG_EVENT_EXIT_THREAD = 0x00000008
DEBUG_EVENT_CREATE_PROCESS = 0x00000010
DEBUG_EVENT_EXIT_PROCESS = 0x00000020
DEBUG_EVENT_LOAD_MODULE = 0x00000040
DEBUG_EVENT_UNLOAD_MODULE = 0x00000080
DEBUG_EVENT_SYSTEM_ERROR = 0x00000100
DEBUG_EVENT_SESSION_STATUS = 0x00000200
DEBUG_EVENT_CHANGE_DEBUGGEE_STATE = 0x00000400
DEBUG_EVENT_CHANGE_ENGINE_STATE = 0x00000800
DEBUG_EVENT_CHANGE_SYMBOL_STATE = 0x00001000

_INTEREST_MASK = (
    DEBUG_EVENT_BREAKPOINT
    | DEBUG_EVENT_EXCEPTION
    | DEBUG_EVENT_LOAD_MODULE
    | DEBUG_EVENT_UNLOAD_MODULE
    | DEBUG_EVENT_SYSTEM_ERROR
    | DEBUG_EVENT_SESSION_STATUS
    | DEBUG_EVENT_CHANGE_ENGINE_STATE
    | DEBUG_EVENT_CHANGE_SYMBOL_STATE
)


class IDebugEventCallbacks(IUnknown):
    """Minimal IDebugEventCallbacks vtable - subset we implement."""

    _iid_ = IID_IDebugEventCallbacks
    _methods_ = [
        COMMETHOD([], HRESULT, "GetInterestMask", (["out"], c_uint, "Mask")),
        COMMETHOD(
            [], HRESULT, "Breakpoint", (["in"], c_void_p, "Bp")
        ),
        COMMETHOD(
            [], HRESULT, "Exception",
            (["in"], c_void_p, "Exception"),
            (["in"], c_uint, "FirstChance"),
        ),
        COMMETHOD(
            [], HRESULT, "CreateThread",
            (["in"], c_ulonglong, "Handle"),
            (["in"], c_ulonglong, "DataOffset"),
            (["in"], c_ulonglong, "StartOffset"),
        ),
        COMMETHOD([], HRESULT, "ExitThread", (["in"], c_uint, "ExitCode")),
        COMMETHOD(
            [], HRESULT, "CreateProcess",
            (["in"], c_ulonglong, "ImageFileHandle"),
            (["in"], c_ulonglong, "Handle"),
            (["in"], c_ulonglong, "BaseOffset"),
            (["in"], c_uint, "ModuleSize"),
            (["in"], c_wchar_p, "ModuleName"),
            (["in"], c_wchar_p, "ImageName"),
            (["in"], c_uint, "CheckSum"),
            (["in"], c_uint, "TimeDateStamp"),
            (["in"], c_ulonglong, "InitialThreadHandle"),
            (["in"], c_ulonglong, "ThreadDataOffset"),
            (["in"], c_ulonglong, "StartOffset"),
        ),
        COMMETHOD([], HRESULT, "ExitProcess", (["in"], c_uint, "ExitCode")),
        COMMETHOD(
            [], HRESULT, "LoadModule",
            (["in"], c_ulonglong, "ImageFileHandle"),
            (["in"], c_ulonglong, "BaseOffset"),
            (["in"], c_uint, "ModuleSize"),
            (["in"], c_wchar_p, "ModuleName"),
            (["in"], c_wchar_p, "ImageName"),
            (["in"], c_uint, "CheckSum"),
            (["in"], c_uint, "TimeDateStamp"),
        ),
        COMMETHOD(
            [], HRESULT, "UnloadModule",
            (["in"], c_wchar_p, "ImageBaseName"),
            (["in"], c_ulonglong, "BaseOffset"),
        ),
        COMMETHOD(
            [], HRESULT, "SystemError",
            (["in"], c_uint, "Error"),
            (["in"], c_uint, "Level"),
        ),
        COMMETHOD([], HRESULT, "SessionStatus", (["in"], c_uint, "Status")),
        COMMETHOD(
            [], HRESULT, "ChangeDebuggeeState",
            (["in"], c_uint, "Flags"),
            (["in"], c_ulonglong, "Argument"),
        ),
        COMMETHOD(
            [], HRESULT, "ChangeEngineState",
            (["in"], c_uint, "Flags"),
            (["in"], c_ulonglong, "Argument"),
        ),
        COMMETHOD(
            [], HRESULT, "ChangeSymbolState",
            (["in"], c_uint, "Flags"),
            (["in"], c_ulonglong, "Argument"),
        ),
    ]


def build_event_callbacks_com_object(handler: Any) -> Any:
    """Wrap a :class:`BinaryMcpEventCallbacks` instance in a COMObject.

    DbgEng will only call us via the IDebugEventCallbacks vtable, so we
    need an object whose ``_com_interfaces_`` lists that interface. The
    handler reference is captured in instance attributes so each method
    dispatches into our pure-Python handler.
    """

    class _ImplBase(comtypes.COMObject):
        _com_interfaces_ = [IDebugEventCallbacks]

        def __init__(self) -> None:
            super().__init__()
            self._handler = handler

        def GetInterestMask(self) -> int:  # type: ignore[override]
            return _INTEREST_MASK

        def Breakpoint(self, bp_ptr: int) -> int:  # type: ignore[override]
            # Resolving the bp_ptr to an ID/address would require
            # additional COM calls; for state-tracking purposes the
            # mere fact that a breakpoint fired is enough.
            return self._handler.on_breakpoint(0, 0)

        def Exception(self, exc_ptr: int, first_chance: int) -> int:  # type: ignore[override]
            return self._handler.on_exception(0, 0, bool(first_chance))

        def CreateThread(self, handle: int, data: int, start: int) -> int:  # type: ignore[override]
            return 0

        def ExitThread(self, code: int) -> int:  # type: ignore[override]
            return 0

        def CreateProcess(self, *_args: Any) -> int:  # type: ignore[override]
            return 0

        def ExitProcess(self, code: int) -> int:  # type: ignore[override]
            return 0

        def LoadModule(
            self,
            image_handle: int,
            base: int,
            size: int,
            module_name: str,
            image_name: str,
            checksum: int,
            timestamp: int,
        ) -> int:  # type: ignore[override]
            return self._handler.on_load_module(
                base, size, module_name or image_name or ""
            )

        def UnloadModule(self, name: str, base: int) -> int:  # type: ignore[override]
            return self._handler.on_unload_module(base, name or "")

        def SystemError(self, error: int, level: int) -> int:  # type: ignore[override]
            return self._handler.on_system_error(error, level)

        def SessionStatus(self, status: int) -> int:  # type: ignore[override]
            return self._handler.on_session_status(status)

        def ChangeDebuggeeState(self, flags: int, arg: int) -> int:  # type: ignore[override]
            return 0

        def ChangeEngineState(self, flags: int, arg: int) -> int:  # type: ignore[override]
            return self._handler.on_change_engine_state(flags, arg)

        def ChangeSymbolState(self, flags: int, arg: int) -> int:  # type: ignore[override]
            return 0

    return _ImplBase()


__all__ = [
    "IDebugEventCallbacks",
    "IID_IDebugEventCallbacks",
    "build_event_callbacks_com_object",
]
