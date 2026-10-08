"""Compile and RUN the C++ listener policy against the cases it must refuse.

``src/engines/dynamic/x64dbg/server/listener_policy.h`` is deliberately free of
Windows headers so that this test can ``#include`` the shipped header, build it
with g++ and execute it. That matters more here than anywhere else in the
project: the rest of obsidian_server cannot be built off Windows, so its only
automated check is the compile job in ci.yml, and "it compiles" says nothing
about whether ``--bind 0.0.0.0`` is refused.

This includes the header rather than extracting functions from it (which is
what tests/test_cpp_request_parsing.py has to do for main.cpp, where the
helpers are embedded in a Windows-only translation unit). Including it is
strictly better: there is no extraction step to drift, and the whole header is
type-checked, not just the functions someone remembered to list.

The emphasis is on refusals. A policy that permitted a wildcard bind, or
plaintext to a LAN address, would pass a happy-path test just as well.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_SERVER_DIR = _REPO / "src" / "engines" / "dynamic" / "x64dbg" / "server"
_POLICY_H = _SERVER_DIR / "listener_policy.h"

_COMPILER = shutil.which("g++") or shutil.which("clang++")

requires_cxx = pytest.mark.skipif(
    _COMPILER is None, reason="no C++ compiler available on this runner"
)


# Each case is (label, argv-after-the-program-name, expectation).
#
# "ok:<describe substring>" expects ParseOptions to succeed and Describe() to
# contain the substring. "err:<substring>" expects a refusal whose message
# contains it -- the message is part of the contract, because an operator who
# is refused needs to be told which flag would have worked.
_HARNESS = r"""
#include "listener_policy.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int failures = 0;

static void fail(const std::string& label, const std::string& detail) {
    failures++;
    printf("FAIL %s: %s\n", label.c_str(), detail.c_str());
}

// --- ParseOptions ---------------------------------------------------------

static void expect_ok(const std::string& label, std::vector<const char*> args,
                      const char* describeContains) {
    args.insert(args.begin(), "obsidian_server");
    Listener::Options options;
    std::string error;
    if (!Listener::ParseOptions((int)args.size(), args.data(), options, error)) {
        fail(label, "refused with: " + error);
        return;
    }
    const std::string described = Listener::Describe(options);
    if (described.find(describeContains) == std::string::npos) {
        fail(label, "Describe() = '" + described + "', wanted '" +
                        std::string(describeContains) + "'");
    }
}

static void expect_err(const std::string& label, std::vector<const char*> args,
                       const char* messageContains) {
    args.insert(args.begin(), "obsidian_server");
    Listener::Options options;
    std::string error;
    if (Listener::ParseOptions((int)args.size(), args.data(), options, error)) {
        fail(label, "ACCEPTED, should have been refused");
        return;
    }
    if (error.find(messageContains) == std::string::npos) {
        fail(label, "message = '" + error + "', wanted '" +
                        std::string(messageContains) + "'");
    }
}

static const char* kThumb = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678";
static const char* kThumb2 = "0011223344556677889900aabbccddeeff001122";

static void test_parse_options() {
    // Defaults: loopback, 8765, no TLS, no allowlist.
    expect_ok("defaults", {}, "http://127.0.0.1:8765");
    expect_ok("defaults-tls-off", {}, "tls=OFF");
    expect_ok("defaults-loopback", {}, "loopback");
    expect_ok("defaults-allowlist-off", {}, "client-allowlist=OFF");

    // The legacy positional port, which every deployed plugin may still use.
    expect_ok("legacy-positional-port", {"9000"}, "http://127.0.0.1:9000");
    expect_ok("flag-port", {"--port", "9000"}, ":9000");

    // A wildcard bind is refused with and without TLS.
    expect_err("wildcard-v4", {"--bind", "0.0.0.0"}, "binds every interface");
    expect_err("wildcard-v6", {"--bind", "::"}, "binds every interface");
    expect_err("wildcard-star", {"--bind", "*"}, "binds every interface");
    expect_err("wildcard-empty", {"--bind", ""}, "binds every interface");
    expect_err("wildcard-with-tls",
               {"--bind", "0.0.0.0", "--tls-cert-thumbprint", kThumb},
               "binds every interface");
    expect_err("wildcard-bracketed-v6", {"--bind", "[::]"}, "binds every interface");

    // Plaintext to a non-loopback host: there is no such configuration.
    expect_err("remote-without-tls", {"--bind", "192.168.1.50"}, "TLS is required");
    expect_ok("remote-with-tls",
              {"--bind", "192.168.1.50", "--tls-cert-thumbprint", kThumb},
              "https://192.168.1.50:8765");
    expect_ok("remote-with-tls-is-remote",
              {"--bind", "192.168.1.50", "--tls-cert-thumbprint", kThumb}, "REMOTE");

    // Loopback needs no TLS and no opt-in, and the whole /8 counts.
    expect_ok("loopback-127-0-0-2", {"--bind", "127.0.0.2"}, "loopback");
    expect_ok("loopback-high", {"--bind", "127.255.255.254"}, "loopback");

    // TLS on loopback is allowed: a local terminator is a real setup.
    expect_ok("loopback-with-tls", {"--tls-cert-thumbprint", kThumb},
              "https://127.0.0.1:8765");

    // Mutual TLS.
    expect_ok("mutual-tls",
              {"--bind", "192.168.1.50", "--tls-cert-thumbprint", kThumb,
               "--tls-client-ca-thumbprint", kThumb2},
              "tls=mutual");
    expect_err("client-ca-without-cert", {"--tls-client-ca-thumbprint", kThumb2},
               "no TLS to verify within");

    // Thumbprints are validated here so a typo is a start-up refusal rather
    // than "certificate not found" later.
    expect_err("short-thumbprint", {"--tls-cert-thumbprint", "abc"},
               "40 hex characters");
    expect_err("non-hex-thumbprint",
               {"--tls-cert-thumbprint", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
               "40 hex characters");
    // Separators as the Windows UI copies them are tolerated, not a typo.
    expect_ok("thumbprint-with-spaces",
              {"--tls-cert-thumbprint",
               "a1 b2 c3 d4 e5 f6 07 18 29 3a 4b 5c 6d 7e 8f 90 12 34 56 78"},
              "tls=server");
    expect_ok("thumbprint-with-colons",
              {"--tls-cert-thumbprint",
               "a1:b2:c3:d4:e5:f6:07:18:29:3a:4b:5c:6d:7e:8f:90:12:34:56:78"},
              "tls=server");

    // Ports.
    expect_err("port-zero", {"--port", "0"}, "outside 1-65535");
    expect_err("port-too-big", {"--port", "65536"}, "outside 1-65535");
    expect_err("port-not-a-number", {"--port", "http"}, "is not a number");
    expect_err("legacy-port-zero", {"0"}, "outside 1-65535");

    // A bind this parser cannot classify is refused, not handed to the OS.
    expect_err("bind-short-form", {"--bind", "127.1"}, "dotted-quad");
    expect_err("bind-octal-looking", {"--bind", "0177.0.0.1"}, "dotted-quad");
    expect_err("bind-name", {"--bind", "localhost"}, "dotted-quad");
    expect_err("bind-ipv6-loopback", {"--bind", "::1"}, "IPv4-only");

    // Allowlist.
    expect_ok("allow-client-host", {"--allow-client", "10.0.0.7"},
              "client-allowlist=1");
    expect_ok("allow-client-cidr", {"--allow-client", "10.0.0.0/24"},
              "client-allowlist=1");
    expect_ok("allow-client-twice",
              {"--allow-client", "10.0.0.0/24", "--allow-client", "192.168.1.5"},
              "client-allowlist=2");
    expect_err("allow-client-garbage", {"--allow-client", "not-an-address"},
               "not a dotted-quad");
    expect_err("allow-client-bad-prefix", {"--allow-client", "10.0.0.0/33"},
               "0-32");

    // Argument hygiene.
    expect_err("unknown-flag", {"--yolo"}, "unknown argument");
    expect_err("missing-value", {"--bind"}, "needs a value");
    expect_err("empty-allow-host", {"--allow-host", ""}, "non-empty");
}

// --- ParseIPv4 ------------------------------------------------------------

static void expect_addr(const char* text, bool wantOk, uint32_t wantAddr) {
    uint32_t addr = 0;
    const bool ok = Listener::ParseIPv4(text, addr);
    if (ok != wantOk || (wantOk && addr != wantAddr)) {
        char detail[128];
        snprintf(detail, sizeof(detail), "ok=%d addr=0x%08x", (int)ok, addr);
        fail(std::string("ParseIPv4 '") + text + "'", detail);
    }
}

static void test_parse_ipv4() {
    expect_addr("0.0.0.0", true, 0x00000000u);
    expect_addr("127.0.0.1", true, 0x7F000001u);
    expect_addr("255.255.255.255", true, 0xFFFFFFFFu);
    expect_addr("192.168.1.50", true, 0xC0A80132u);
    // Everything inet_addr would additionally accept is refused, so this
    // parser and the bind call cannot disagree about what an address means.
    expect_addr("127.1", false, 0);
    expect_addr("127.0.1", false, 0);
    expect_addr("0177.0.0.1", false, 0);
    expect_addr("010.0.0.1", false, 0);
    expect_addr("0", false, 0);
    expect_addr("256.0.0.1", false, 0);
    expect_addr("1.2.3.4.5", false, 0);
    expect_addr("1.2.3.", false, 0);
    expect_addr(".1.2.3", false, 0);
    expect_addr("1.2.3.4 ", false, 0);
    expect_addr(" 1.2.3.4", false, 0);
    expect_addr("1.2.3.-4", false, 0);
    expect_addr("1.2.3.0x4", false, 0);
    expect_addr("", false, 0);
    expect_addr("1234.1.1.1", false, 0);
    // A single zero octet is fine; it is only a LEADING zero that is ambiguous.
    expect_addr("10.0.0.1", true, 0x0A000001u);
}

// --- ClientAllowed --------------------------------------------------------

static Listener::Options with_allowlist(std::vector<const char*> entries) {
    Listener::Options options;
    for (size_t i = 0; i < entries.size(); i++) {
        Listener::Cidr range;
        std::string error;
        if (!Listener::ParseCidr(entries[i], range, error)) {
            fail("with_allowlist", error);
            continue;
        }
        options.clientAllowlist.push_back(range);
    }
    return options;
}

static void expect_client(const std::string& label, const Listener::Options& options,
                          const char* peer, bool want) {
    uint32_t addr = 0;
    if (!Listener::ParseIPv4(peer, addr)) {
        fail(label, std::string("test peer unparseable: ") + peer);
        return;
    }
    if (Listener::ClientAllowed(options, addr) != want) {
        fail(label, std::string("peer ") + peer + " wanted " + (want ? "allow" : "deny"));
    }
}

static void test_client_allowed() {
    // No allowlist: any peer may present a token. The documented default.
    const Listener::Options open;
    expect_client("open-any", open, "203.0.113.9", true);

    const Listener::Options cidr = with_allowlist({"10.0.0.0/24"});
    expect_client("cidr-in", cidr, "10.0.0.7", true);
    expect_client("cidr-edge-low", cidr, "10.0.0.0", true);
    expect_client("cidr-edge-high", cidr, "10.0.0.255", true);
    expect_client("cidr-out", cidr, "10.0.1.1", false);
    expect_client("cidr-far", cidr, "192.168.1.1", false);

    // A bare address is a single host, not a range.
    const Listener::Options host = with_allowlist({"10.0.0.7"});
    expect_client("host-exact", host, "10.0.0.7", true);
    expect_client("host-neighbour", host, "10.0.0.8", false);

    // Several entries: any match allows.
    const Listener::Options both = with_allowlist({"10.0.0.0/24", "192.168.1.5"});
    expect_client("both-first", both, "10.0.0.99", true);
    expect_client("both-second", both, "192.168.1.5", true);
    expect_client("both-neither", both, "172.16.0.1", false);

    // /0 means everything -- an operator may write it, and it must behave.
    const Listener::Options all = with_allowlist({"0.0.0.0/0"});
    expect_client("slash-zero", all, "203.0.113.9", true);

    // /32 is the explicit single host.
    const Listener::Options exact = with_allowlist({"10.0.0.7/32"});
    expect_client("slash-32-in", exact, "10.0.0.7", true);
    expect_client("slash-32-out", exact, "10.0.0.6", false);
}

// --- Host / Origin --------------------------------------------------------

static void expect_host(const std::string& label, const Listener::Options& options,
                        const char* value, bool want) {
    if (Listener::HostAllowed(options, value) != want) {
        fail(label, std::string("Host '") + value + "' wanted " +
                        (want ? "allow" : "deny"));
    }
}

static void test_host_allowed() {
    Listener::Options loop;  // bind defaults to 127.0.0.1

    expect_host("loop-ip-port", loop, "127.0.0.1:8765", true);
    expect_host("loop-ip-bare", loop, "127.0.0.1", true);
    expect_host("loop-localhost", loop, "localhost:8765", true);
    expect_host("loop-v6", loop, "[::1]:8765", true);
    expect_host("loop-mixed-case", loop, "LOCALHOST:8765", true);
    expect_host("loop-foreign", loop, "evil.test", false);
    expect_host("loop-foreign-port", loop, "evil.test:8765", false);
    expect_host("loop-empty", loop, "", false);

    Listener::Options remote;
    remote.bind = "192.168.1.50";
    expect_host("remote-ip", remote, "192.168.1.50:8765", true);
    // A LAN listener does not answer for localhost: nobody dials it that way,
    // and accepting it would weaken the rebinding check for nothing.
    expect_host("remote-not-localhost", remote, "localhost", false);
    expect_host("remote-foreign", remote, "evil.test", false);

    remote.allowedHosts.push_back("analysis.lan");
    expect_host("remote-allowed-name", remote, "analysis.lan:8765", true);
    expect_host("remote-allowed-name-case", remote, "Analysis.LAN", true);
    expect_host("remote-still-foreign", remote, "other.lan", false);
}

static void expect_strip(const char* label, const char* in, const char* want,
                         bool origin) {
    const std::string got =
        origin ? Listener::StripOrigin(in) : Listener::StripHostPort(in);
    if (got != want) {
        fail(label, std::string("got '") + got + "' wanted '" + want + "'");
    }
}

static void test_strip() {
    expect_strip("host-port", "192.168.1.50:8765", "192.168.1.50", false);
    expect_strip("host-bare", "192.168.1.50", "192.168.1.50", false);
    expect_strip("host-v6-port", "[::1]:8765", "::1", false);
    expect_strip("host-v6-bare", "[::1]", "::1", false);
    // A bare IPv6 literal has several colons: splitting on ':' would leave an
    // empty host and refuse a legitimate request.
    expect_strip("host-v6-unbracketed", "::1", "::1", false);
    expect_strip("host-v6-long", "fe80::1", "fe80::1", false);
    expect_strip("host-case", "Example.TEST:80", "example.test", false);

    expect_strip("origin-https", "https://example.test:8765", "example.test", true);
    expect_strip("origin-http", "http://127.0.0.1:8765", "127.0.0.1", true);
    expect_strip("origin-v6", "https://[::1]:8765", "::1", true);
    expect_strip("origin-null", "null", "null", true);
    expect_strip("origin-no-scheme", "example.test", "example.test", true);
}

static void expect_count(const char* label, const std::string& request,
                         const char* name, size_t want) {
    const size_t got = Listener::CountHeaderOccurrences(request, name);
    if (got != want) {
        char detail[96];
        snprintf(detail, sizeof(detail), "got %zu want %zu", got, want);
        fail(label, detail);
    }
}

static void test_count_headers() {
    expect_count("one", "GET / HTTP/1.1\r\nHost: a\r\n\r\n", "Host", 1);
    expect_count("two", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "Host", 2);
    expect_count("none", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "Host", 0);
    expect_count("case", "GET / HTTP/1.1\r\nhost: a\r\nHOST: b\r\n\r\n", "Host", 2);
    // A name that merely CONTAINS the one wanted is not it.
    expect_count("longer-name", "GET / HTTP/1.1\r\nX-Host: a\r\nHost: b\r\n\r\n",
                 "Host", 1);
    // The body is not the header section.
    expect_count("body", "POST / HTTP/1.1\r\nHost: a\r\n\r\nHost: b", "Host", 1);
    // Nor is the request line, including one crafted to look like the header.
    expect_count("request-line", "GET /Host: x HTTP/1.1\r\nAccept: */*\r\n\r\n",
                 "Host", 0);
    expect_count("origin-two",
                 "GET / HTTP/1.1\r\nOrigin: http://a\r\nOrigin: http://b\r\n\r\n",
                 "Origin", 2);
    // Degenerate input must not run off the end.
    expect_count("truncated", "GET / HTTP/1.1\r\nHost: a", "Host", 1);
    expect_count("empty", "", "Host", 0);
    expect_count("no-crlf", "GET / HTTP/1.1", "Host", 0);
}

int main() {
    test_count_headers();
    test_parse_options();
    test_parse_ipv4();
    test_client_allowed();
    test_host_allowed();
    test_strip();
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@pytest.fixture(scope="module")
def policy_binary(tmp_path_factory):
    """Compile the harness against the shipped header once for the module."""
    if _COMPILER is None:
        pytest.skip("no C++ compiler available on this runner")
    workdir = tmp_path_factory.mktemp("listener_policy")
    source = workdir / "harness.cpp"
    source.write_text(_HARNESS, encoding="utf-8")
    # Named with the platform's executable suffix. A Windows compiler emits
    # harness.exe, so an extensionless path is not the file that appears --
    # which made the is_file() assertion below fail on windows-latest while
    # test_policy_decisions right next to it PASSED, because CreateProcess
    # appends .exe to an extensionless path and ran the binary anyway. Naming
    # it keeps the path asserted on and the path executed identical instead of
    # resting on that fallback.
    binary = workdir / ("harness.exe" if os.name == "nt" else "harness")
    compile_result = subprocess.run(
        [
            _COMPILER,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{_SERVER_DIR}",
            str(source),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
    )
    assert compile_result.returncode == 0, (
        "listener_policy.h did not compile cleanly:\n" + compile_result.stderr
    )
    return binary


@requires_cxx
def test_header_exists():
    """A silent deletion of the policy header must fail a test, not a release."""
    assert _POLICY_H.is_file(), f"{_POLICY_H} is gone"


@requires_cxx
def test_policy_compiles_without_warnings(policy_binary):
    """-Werror here, matching the warnings-as-errors gate ci.yml applies on Windows.

    The header is included by a Windows-only translation unit in production, so
    a warning that only MSVC emits would be caught there; this catches the ones
    gcc sees, which has historically been the larger set for sign and
    comparison defects.
    """
    assert policy_binary.is_file()


@requires_cxx
def test_policy_decisions(policy_binary):
    """Run every case. The harness prints one FAIL line per wrong decision."""
    run = subprocess.run([str(policy_binary)], capture_output=True, text=True)
    assert run.returncode == 0, "listener policy made wrong decisions:\n" + run.stdout
    assert "failures=0" in run.stdout


# --------------------------------------------------------------------------
# Source-level guards for the Windows-only parts
# --------------------------------------------------------------------------
#
# These cannot be executed here, so they are pinned by presence. Weaker than
# running them, and better than nothing: each one is a line whose deletion
# would quietly re-open something this change closed.

_MAIN_CPP = _SERVER_DIR / "main.cpp"


def test_server_no_longer_sends_a_cors_wildcard():
    """`Access-Control-Allow-Origin: *` has no place on this listener.

    It was on every response, including the 401. There is no browser client, so
    it granted nothing legitimate; what it did do was invite exactly the
    cross-origin access the Host/Origin check now refuses. A later addition of
    Access-Control-Allow-Headers would have made it reachable.
    """
    source = _MAIN_CPP.read_text(encoding="utf-8")
    # Matched as it would appear in a C++ string literal being built, not as a
    # bare name: the comment that explains why the header is gone names it, and
    # that comment is worth keeping.
    assert '"Access-Control-Allow-Origin:' not in source, (
        "main.cpp sends an Access-Control-Allow-Origin header again"
    )
    assert '"Access-Control-Allow-Headers:' not in source, (
        "main.cpp sends an Access-Control-Allow-Headers header, which is what "
        "would make the wildcard reachable from a browser"
    )


def test_server_validates_host_before_dispatch():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    assert "Listener::HostAllowed" in source, (
        "main.cpp no longer checks the Host header; a listener off loopback is "
        "then open to DNS rebinding"
    )
    assert "Listener::CountHeaderOccurrences" in source, (
        "main.cpp no longer refuses a duplicated Host/Origin, so it would "
        "decide on one value while a proxy in front decided on another"
    )


def test_server_binds_the_configured_address_not_a_constant():
    """INADDR_LOOPBACK was hardcoded; the policy must decide the bind now."""
    source = _MAIN_CPP.read_text(encoding="utf-8")
    assert "htonl(INADDR_LOOPBACK)" not in source, (
        "main.cpp hardcodes the loopback bind again, so --bind cannot work"
    )
    assert "Listener::ParseOptions" in source, (
        "main.cpp no longer parses listener options"
    )


def test_server_checks_the_client_allowlist_at_accept():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    assert "Listener::ClientAllowed" in source, (
        "main.cpp no longer applies the client allowlist"
    )


# --------------------------------------------------------------------------
# The documented setup is part of the contract
# --------------------------------------------------------------------------
#
# docs/remote-access.md carries the PowerShell an operator pastes to expose the
# listener. There is no PowerShell on the CI runners, so it cannot be executed
# -- but the two properties that make it safe rather than convenient are
# textual, and a doc edit that loses either is a doc edit that tells someone to
# open their debugger to the network. Pinned here for the same reason
# test_docs_accuracy.py pins the security-model claims: prose has no compiler.

_REMOTE_ACCESS_DOC = _REPO / "docs" / "remote-access.md"


def test_documented_firewall_rule_is_scoped_to_a_client():
    """The New-NetFirewallRule example must carry -RemoteAddress.

    Without it the rule is scoped to Any, which turns "reachable from the
    analyst's workstation" into "reachable from the network the malware VM is
    on" -- the exact outcome the client allowlist and the wildcard-bind refusal
    exist to prevent.
    """
    doc = _REMOTE_ACCESS_DOC.read_text(encoding="utf-8")
    assert "New-NetFirewallRule" in doc, (
        "docs/remote-access.md no longer documents the firewall rule the direct "
        "path needs"
    )
    for line in doc.splitlines():
        if "New-NetFirewallRule" in line:
            block_start = doc.index(line)
            # The rule spans continuation lines; take the fenced block it is in.
            block = doc[block_start : doc.index("```", block_start)]
            assert "-RemoteAddress" in block, (
                "the documented firewall rule has no -RemoteAddress, so it is "
                "scoped to Any"
            )
            assert "-Profile Private" in block, (
                "the documented firewall rule does not restrict the profile"
            )
            break


def test_documented_setup_never_binds_a_wildcard():
    """No example may show 0.0.0.0 as something to configure.

    The server refuses it, so an example containing it would only teach an
    operator to try a thing that cannot work -- or, worse, read as advice.
    """
    doc = _REMOTE_ACCESS_DOC.read_text(encoding="utf-8")
    for line in doc.splitlines():
        stripped = line.strip()
        if "0.0.0.0" not in stripped:
            continue
        # Allowed only where it is named as refused, or as a CIDR prefix.
        narrative = any(
            word in stripped for word in ("refused", "wildcard", "0.0.0.0/0")
        )
        assert narrative, f"docs/remote-access.md shows a wildcard bind: {stripped!r}"


def test_documented_ini_keys_match_the_plugin():
    """Every [listener] key in the docs is one the plugin actually reads.

    A documented key the plugin ignores is a setting an operator believes they
    have applied -- the same class of defect as the four dead CONFIG_KEYS
    entries this branch removed on the Python side.
    """
    import re

    doc = _REMOTE_ACCESS_DOC.read_text(encoding="utf-8")
    plugin = (
        _REPO / "src" / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"
    ).read_text(encoding="utf-8")

    # Keys shown in an ini fence: `key=value` lines under a [listener] header.
    documented = set()
    in_ini = False
    for line in doc.splitlines():
        if line.strip() == "[listener]":
            in_ini = True
            continue
        if line.startswith("```"):
            in_ini = False
            continue
        if in_ini:
            match = re.match(r"^([a-z_]+)\s*=", line.strip())
            if match:
                documented.add(match.group(1))

    assert documented, "docs/remote-access.md no longer shows any [listener] keys"
    for key in sorted(documented):
        assert f'"{key}"' in plugin, (
            f"docs/remote-access.md documents [listener] {key}, but plugin.cpp "
            f"does not read it"
        )
