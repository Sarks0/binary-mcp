"""
Executable verification for the C++ HTTP header parser and output confinement.

The C++ in this repo targets Windows/MSVC and is not built by CI, so it has
historically been reviewed by reading only. Two of the fixes in this branch are
pure ``std::string`` logic with no Windows dependency at all, which means they
CAN be compiled and run here -- and the bugs they fix were both the kind a
careful read had already missed once:

* ``FindHeaderValue`` replaced ``request.find("Content-Length:")``. That search
  was unanchored, so ``X-My-Content-Length:`` contained it and, being
  earliest-match, beat the real header; and it matched only two hard-coded
  spellings, so RFC 9110's case-insensitive ``Content-length:`` silently read as
  "no body". Both reachable before authentication.
* ``ResolveConfinedOutputPath`` gained a reparse-point walk. ``GetFullPathNameA``
  is purely lexical, so a junction planted inside the output root kept the
  prefix check happy while redirecting the write out of the root.

The header functions are extracted VERBATIM from main.cpp and compiled, so this
tests the shipped source rather than a copy that can drift. The confinement walk
cannot be extracted cleanly (it is an inline block inside a large Windows-only
function), so it gets a source-level presence guard instead -- enough to stop a
silent deletion.

Skips when no C++ compiler is available, e.g. on the Windows CI runner.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_MAIN_CPP = _REPO / "src" / "engines" / "dynamic" / "x64dbg" / "server" / "main.cpp"
_PLUGIN_CPP = _REPO / "src" / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"

_COMPILER = shutil.which("g++") or shutil.which("clang++")

requires_cxx = pytest.mark.skipif(
    _COMPILER is None, reason="no C++ compiler available on this runner"
)


def _extract_function(source: str, signature: str) -> str:
    """Pull one free function out of a translation unit, verbatim.

    Relies on the file's own formatting: the closing brace of a top-level
    function is the first ``\\n}`` at column zero after the signature.
    """
    start = source.index(signature)
    end = source.index("\n}\n", start) + len("\n}\n")
    return source[start:end]


# The harness only needs the two pure-logic helpers; everything else in main.cpp
# is Windows-only and irrelevant to header parsing.
_TEST_MAIN = r"""
// The marker below is replaced with helpers copied verbatim from main.cpp.
// Keep exactly one occurrence of it in this template.
#include <string>
#include <cstring>
#include <cstdio>

@@EXTRACTED@@

static int failures = 0;

static void check(const char* label, const std::string& req, const char* name,
                  bool wantFound, const char* wantVal) {
    std::string v;
    bool got = FindHeaderValue(req, name, v);
    bool ok = (got == wantFound) && (!wantFound || v == wantVal);
    if (!ok) {
        failures++;
        printf("FAIL %s (found=%d value='%s')\n", label, (int)got, v.c_str());
    }
}

int main() {
    // The spoof: a header whose NAME CONTAINS the one we want, placed first.
    check("spoof-longer-name",
          "POST / HTTP/1.1\r\nX-My-Content-Length: 1048576\r\nContent-Length: 5\r\n\r\nhello",
          "Content-Length", true, "5");
    // RFC 9110 case-insensitivity: both of these used to read as "no body".
    check("case-mixed", "POST / HTTP/1.1\r\nContent-length: 12\r\n\r\n",
          "Content-Length", true, "12");
    check("case-upper", "POST / HTTP/1.1\r\nCONTENT-LENGTH: 12\r\n\r\n",
          "Content-Length", true, "12");
    // The body is not the header section.
    check("body-not-scanned", "POST / HTTP/1.1\r\nHost: x\r\n\r\nContent-Length: 999",
          "Content-Length", false, "");
    // Nor is the request line -- including a first line crafted to look
    // EXACTLY like the header. Without the request-line skip this parses as a
    // header; the weaker "GET /Content-Length: ..." form does not catch that,
    // because the method turns the name into "GET /Content-Length".
    check("request-line-not-header", "GET /Content-Length: 9 HTTP/1.1\r\nHost: x\r\n\r\n",
          "Content-Length", false, "");
    check("request-line-spoofing-header", "Content-Length: 999\r\nHost: x\r\n\r\n",
          "Content-Length", false, "");
    check("absent", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "Content-Length", false, "");
    check("ows-trimmed", "POST / HTTP/1.1\r\nContent-Length:\t 42  \r\n\r\n",
          "Content-Length", true, "42");
    // Authorization goes through the same lookup.
    check("auth-normal", "GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n",
          "Authorization", true, "Bearer abc123");
    check("auth-spoof", "GET / HTTP/1.1\r\nX-Not-Authorization: Bearer evil\r\n\r\n",
          "Authorization", false, "");
    check("auth-lowercase", "GET / HTTP/1.1\r\nauthorization: Bearer tok\r\n\r\n",
          "Authorization", true, "Bearer tok");
    // Truncated / degenerate input must not run off the end.
    check("no-terminator", "GET / HTTP/1.1\r\nContent-Length: 7", "Content-Length", true, "7");
    check("empty", "", "Content-Length", false, "");
    check("no-crlf", "GET / HTTP/1.1", "Content-Length", false, "");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_header_lookup_is_anchored_and_case_insensitive(tmp_path):
    """Compile the SHIPPED helpers and run them against the bypasses."""
    source = _MAIN_CPP.read_text(encoding="utf-8")
    extracted = "\n".join(
        (
            _extract_function(source, "static bool AsciiEqualsIgnoreCase"),
            _extract_function(source, "static bool FindHeaderValue"),
        )
    )

    assert _TEST_MAIN.count("@@EXTRACTED@@") == 1, (
        "harness template must contain exactly one substitution marker; a "
        "second one (e.g. inside a comment) pastes the helpers above the "
        "#include lines and the failure looks like a C++ error, not a test bug"
    )

    harness = tmp_path / "hdr_test.cpp"
    harness.write_text(_TEST_MAIN.replace("@@EXTRACTED@@", extracted), encoding="utf-8")

    binary = tmp_path / "hdr_test"
    compile_result = subprocess.run(
        [_COMPILER, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O1",
         str(harness), "-o", str(binary)],
        capture_output=True,
        text=True,
    )
    assert compile_result.returncode == 0, (
        "extracted header helpers did not compile:\n" + compile_result.stderr
    )

    run_result = subprocess.run([str(binary)], capture_output=True, text=True)
    assert run_result.returncode == 0, (
        "header lookup behaved incorrectly:\n" + run_result.stdout
    )


def test_header_lookup_has_no_unanchored_substring_search():
    """The bug was a bare find() on a header name. Keep it gone.

    Runs everywhere, compiler or not.
    """
    source = _MAIN_CPP.read_text(encoding="utf-8")
    offenders = [
        stripped
        for line in source.splitlines()
        # Skip comments: the rationale above the fix necessarily quotes the
        # very pattern being banned.
        if not (stripped := line.strip()).startswith("//")
        and re.search(r'\.find\(\s*"(?:[A-Za-z-]*)(?:Content-Length|Authorization):', line)
    ]
    assert not offenders, (
        "unanchored header substring search reintroduced (CWE-20); use "
        "FindHeaderValue instead:\n  " + "\n  ".join(offenders)
    )


def test_output_confinement_still_walks_for_reparse_points():
    """GetFullPathNameA is lexical; the reparse-point walk is the physical control.

    A source-level guard because the walk is an inline block inside a
    Windows-only function and cannot be extracted for compilation.
    """
    source = _PLUGIN_CPP.read_text(encoding="utf-8")

    assert "static bool IsReparsePoint(" in source, (
        "IsReparsePoint helper removed; output confinement would be lexical "
        "only and a junction inside the output root would bypass it (CWE-59)"
    )

    # The root itself must be checked -- a junction planted AS the root
    # redirects every write, and CreateDirectoryA's ERROR_ALREADY_EXISTS is
    # indistinguishable from "someone put a junction here".
    root_fn = source[source.index("static bool GetOutputRoot("):]
    root_fn = root_fn[: root_fn.index("\n}\n")]
    assert root_fn.count("IsReparsePoint(") >= 2, (
        "GetOutputRoot must reject a reparse point at BOTH levels it creates"
    )

    # ...and every component below it.
    resolve_fn = source[source.index("static bool ResolveConfinedOutputPath("):]
    resolve_fn = resolve_fn[: resolve_fn.index("\n}\n")]
    assert "IsReparsePoint(component)" in resolve_fn, (
        "ResolveConfinedOutputPath must walk path components for reparse "
        "points; the lexical prefix check alone proves spelling, not location"
    )


def test_body_read_uses_actual_bytes_read():
    """CWE-252: the frame length promised by the peer is not what was read."""
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    assert "std::string request(buffer.data(), bytesRead);" in source, (
        "request frame must be built from bytesRead, not the declared "
        "requestLength -- they differ on a short read"
    )


def test_pipe_handle_publication_is_locked():
    """CWE-362: g_pipeServer is read by pluginStop under g_pipeHandleLock."""
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    assert re.search(
        r"EnterCriticalSection\(&g_pipeHandleLock\);\s*\n\s*g_pipeServer = pipe;",
        source,
    ), "g_pipeServer must be published while holding g_pipeHandleLock"
