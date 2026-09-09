"""
Executable verification for obsidian_server's JSONL activity log.

Following the pattern in test_cpp_request_parsing.py: activity_log.h is
compiled and run here rather than reviewed by eye. It is a good candidate --
the only Windows dependencies are a handful of Win32 calls that stub cleanly,
and the parts worth checking (JSON escaping, the body opt-in, crash
survivability) are pure string logic.

The header is compiled AS SHIPPED, not as a copy, so these cannot drift from
the source.

Two properties matter beyond "it runs":

* Every line must be valid JSON on its own. That is the whole reason the log
  is JSONL rather than one document -- a server that dies mid-write is exactly
  the server whose log you need, and a truncated document parses to nothing.
* Request and response bodies must stay out unless OBSIDIAN_LOG_BODIES=1. A
  body here carries debuggee memory and sample-chosen paths; the F-10
  remediation keeps that out of model context, and it has no more business
  sitting in plaintext on disk.

Skips when no C++ compiler is available, e.g. on the Windows CI runner.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_COMPILER = shutil.which("g++") or shutil.which("clang++")

HEADER = Path("src/engines/dynamic/x64dbg/server/activity_log.h")

# Minimal stand-ins for the Win32 surface activity_log.h touches.
WINDOWS_H = """
#pragma once
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
typedef unsigned long DWORD; typedef void* HANDLE; typedef int BOOL;
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define ERROR_ALREADY_EXISTS 183
struct SYSTEMTIME { unsigned short wYear,wMonth,wDayOfWeek,wDay,wHour,
                    wMinute,wSecond,wMilliseconds; };
struct WIN32_FIND_DATAA { DWORD dwFileAttributes; char cFileName[MAX_PATH]; };
inline void GetSystemTime(SYSTEMTIME* st){
    st->wYear=2026; st->wMonth=9; st->wDay=9; st->wHour=15;
    st->wMinute=42; st->wSecond=7; st->wMilliseconds=123; }
inline void GetLocalTime(SYSTEMTIME* st){ GetSystemTime(st); }
inline DWORD GetCurrentProcessId(){ return 8124; }
inline DWORD GetLastError(){ return 0; }
inline unsigned long long GetTickCount64(){ static unsigned long long t=1000;
    return t += 13; }
inline BOOL CreateDirectoryA(const char* p, void*){ return mkdir(p,0755)==0; }
inline HANDLE FindFirstFileA(const char*, WIN32_FIND_DATAA*){
    return INVALID_HANDLE_VALUE; }
inline BOOL FindNextFileA(HANDLE, WIN32_FIND_DATAA*){ return 0; }
inline BOOL FindClose(HANDLE){ return 1; }
inline BOOL DeleteFileA(const char*){ return 1; }
"""

# Exercises the paths a real request takes, plus a string built to break naive
# escaping: quotes, a backslash, a newline, a tab and a control character.
DRIVER = r"""
#include "activity_log.h"
int main() {
    ActivityLog::Init("./", "1.1.0-rc1", 8765);
    unsigned long long id = ActivityLog::NextRequestId();
    unsigned long long t0 = ActivityLog::NowMs();
    ActivityLog::Event("request.received")
        .Num("id", (long long)id).Str("method", "POST")
        .Str("path", "/api/memory/read").Num("req_bytes", 148);
    ActivityLog::Event("pipe.roundtrip")
        .Num("id", (long long)id).Num("ms", 7).Num("win_err", 0)
        .Body("request", "{\"address\":\"0x7ff600001000\"}");
    ActivityLog::Event("log")
        .Str("msg", "said \"hi\" back\\slash\nnewline\ttab\002ctrl");
    ActivityLog::Event("request.completed")
        .Num("id", (long long)id).Num("status", 200)
        .Num("resp_bytes", 1052)
        .Num("ms", (long long)(ActivityLog::NowMs() - t0));
    ActivityLog::Shutdown(true, "normal shutdown");
    return 0;
}
"""


_RUN_COUNTER = itertools.count()


def _run(base_path: Path, env_extra: dict | None = None) -> list[dict]:
    """Compile the shipped header with the driver, run it, parse the JSONL."""
    # A test may call this several times; give each run its own directory so
    # the second does not trip over the first's output.
    tmp_path = base_path / f"run{next(_RUN_COUNTER)}"
    tmp_path.mkdir(parents=True, exist_ok=True)
    win = tmp_path / "win"
    win.mkdir(exist_ok=True)
    (win / "Windows.h").write_text(WINDOWS_H, encoding="utf-8")
    (tmp_path / "activity_log.h").write_text(
        HEADER.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "driver.cpp").write_text(DRIVER, encoding="utf-8")

    binary = tmp_path / "driver"
    compiled = subprocess.run(
        [
            _COMPILER, "-std=c++17", "-I", str(win), "-I", str(tmp_path),
            # Warnings are errors in CI for this target, so hold the same bar.
            "-Wall", "-Wextra", "-Werror",
            "-o", str(binary), str(tmp_path / "driver.cpp"),
        ],
        capture_output=True, text=True,
    )
    assert compiled.returncode == 0, compiled.stderr

    env = dict(os.environ)
    env.pop("OBSIDIAN_LOG_BODIES", None)
    env.update(env_extra or {})
    run = subprocess.run([str(binary)], cwd=tmp_path, capture_output=True,
                         text=True, env=env)
    assert run.returncode == 0, run.stderr

    # The header builds "<dir>logs\\<name>"; on a POSIX filesystem the
    # backslash is an ordinary filename character, so the file lands beside
    # the driver rather than in a subdirectory. Either way, find it.
    produced = list(tmp_path.rglob("*.jsonl")) + [
        p for p in tmp_path.iterdir() if p.name.endswith(".jsonl")
    ]
    assert produced, f"no log written; dir held {[p.name for p in tmp_path.iterdir()]}"
    text = produced[0].read_text(encoding="utf-8")
    return [json.loads(line) for line in text.split("\n") if line]


@pytest.mark.skipif(_COMPILER is None, reason="no C++ compiler available")
class TestActivityLog:
    def test_every_line_is_valid_json(self, tmp_path):
        events = _run(tmp_path)
        assert len(events) >= 6

    def test_every_event_carries_a_timestamp_and_name(self, tmp_path):
        for event in _run(tmp_path):
            assert event["ts"].endswith("Z"), event
            assert event["ev"], event

    def test_lifecycle_brackets_the_run(self, tmp_path):
        events = _run(tmp_path)
        assert events[0]["ev"] == "server.start"
        assert events[-1]["ev"] == "server.stop"
        assert events[-1]["ok"] is True
        assert events[-1]["requests"] == 1

    def test_start_records_the_build_and_port(self, tmp_path):
        start = _run(tmp_path)[0]
        assert start["version"] == "1.1.0-rc1"
        assert start["port"] == 8765
        assert start["pid"] == 8124

    def test_requests_are_correlated_by_id(self, tmp_path):
        events = _run(tmp_path)
        ids = {e["id"] for e in events if "id" in e}
        assert ids == {1}, "one request should produce one id across its events"

    def test_hostile_string_round_trips_exactly(self, tmp_path):
        """Quotes, backslash, newline, tab and a control char must survive."""
        msg = [e for e in _run(tmp_path) if e["ev"] == "log"][0]["msg"]
        assert msg == 'said "hi" back\\slash\nnewline\ttab\x02ctrl'


@pytest.mark.skipif(_COMPILER is None, reason="no C++ compiler available")
class TestBodiesAreOptIn:
    """Bodies carry debuggee memory and sample paths -- never on by default."""

    def test_body_is_omitted_by_default(self, tmp_path):
        pipe = [e for e in _run(tmp_path) if e["ev"] == "pipe.roundtrip"][0]
        assert "request" not in pipe
        assert _run(tmp_path)[0]["bodies_logged"] is False

    def test_body_is_captured_only_when_explicitly_enabled(self, tmp_path):
        events = _run(tmp_path, {"OBSIDIAN_LOG_BODIES": "1"})
        pipe = [e for e in events if e["ev"] == "pipe.roundtrip"][0]
        assert pipe["request"] == '{"address":"0x7ff600001000"}'
        assert events[0]["bodies_logged"] is True

    def test_a_non_exact_value_does_not_enable_bodies(self, tmp_path):
        # "true", "yes", "10" must not switch on disclosure by accident.
        for value in ("0", "true", "yes", "10", ""):
            events = _run(tmp_path, {"OBSIDIAN_LOG_BODIES": value})
            assert events[0]["bodies_logged"] is False, value


class TestSourceGuards:
    """Cheap invariants that hold whether or not a compiler is present."""

    def test_the_auth_token_is_never_logged(self):
        source = Path("src/engines/dynamic/x64dbg/server/main.cpp").read_text(
            encoding="utf-8"
        )
        for line in source.split("\n"):
            if "ActivityLog::" in line:
                assert "g_authToken" not in line, line

    def test_retention_is_bounded(self):
        header = HEADER.read_text(encoding="utf-8")
        assert "MAX_LOG_FILES" in header
        assert "MAX_LOG_BYTES" in header

    def test_log_is_flushed_per_line(self):
        # An unflushed buffer is lost in exactly the crash this log explains.
        assert "fflush" in HEADER.read_text(encoding="utf-8")
