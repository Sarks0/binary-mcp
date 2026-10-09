"""What .env is allowed to publish into os.environ, and what it is not.

A .env used to be a private config source: it filled _config_cache and
nothing else could see it. That made every reader going straight to
os.environ -- urllib for no_proxy, runner.py for GHIDRA_MAX_HEAP_MB,
security.py for BINARY_MCP_ALLOWED_DIRS -- silently ignore it, so an operator
set a value, saw no error, and got the built-in default.

Publishing it fixes that, and makes the environment of the Ghidra JVM a thing
worth being careful about: runner.py builds that subprocess env from
os.environ.copy(), and the JVM parses untrusted samples. These tests pin both
halves -- what must get through, and what must not.
"""

from __future__ import annotations

import os

import pytest

import src.utils.config as config_module
from src.utils.config import CONFIG_KEYS, _export_to_environ


@pytest.fixture
def exported(monkeypatch):
    """Run the export over a given .env and report what reached os.environ.

    The teardown is not optional. _export_to_environ writes to os.environ
    directly -- that is its whole job -- so monkeypatch never sees those writes
    and cannot undo them. Without the cleanup below, the first version of this
    file left BINARY_MCP_ALLOWED_DIRS=/srv/quarantine and BINARY_CACHE_DIR=/srv/c
    set for the rest of the session and broke 213 later tests by redirecting
    path confinement at a directory that does not exist.
    """
    touched: list[str] = []

    def _run(values: dict[str, str], preset: dict[str, str] | None = None):
        for key in list(values) + list(preset or {}):
            monkeypatch.delenv(key, raising=False)
        for key, value in (preset or {}).items():
            monkeypatch.setenv(key, value)
        touched.extend(values)
        _export_to_environ(values)
        return {key: os.environ.get(key) for key in values}

    yield _run

    # Before monkeypatch's own teardown, which then restores any pre-test value.
    for key in touched:
        os.environ.pop(key, None)


class TestDeclaredSettingsAreExported:
    def test_a_config_key_read_off_os_environ_gets_through(self, exported):
        """GHIDRA_MAX_HEAP_MB is the case that started this.

        runner.py reads it from os.environ to build _JAVA_OPTIONS, so a .env
        value that never reached the environment meant Ghidra ran at the 4096m
        default -- the exact OOM an operator sets it to prevent.
        """
        assert exported({"GHIDRA_MAX_HEAP_MB": "2048"}) == {
            "GHIDRA_MAX_HEAP_MB": "2048"
        }

    def test_the_path_confinement_keys_get_through(self, exported):
        """security.py reads both straight off os.environ."""
        result = exported(
            {"BINARY_MCP_ALLOWED_DIRS": "/srv/quarantine", "BINARY_CACHE_DIR": "/srv/c"}
        )
        assert result == {
            "BINARY_MCP_ALLOWED_DIRS": "/srv/quarantine",
            "BINARY_CACHE_DIR": "/srv/c",
        }

    def test_proxy_passthrough_gets_through(self, exported):
        """no_proxy is consumed by urllib, per request, from the environment.

        It cannot live in CONFIG_KEYS -- test_no_config_key_is_dead requires
        every entry there to be read by something under src/, and nothing of
        ours reads this one. _PASSTHROUGH_ENV_KEYS is where it is declared
        instead, so that it works by intent rather than by the filter
        happening to be permissive.
        """
        assert exported({"no_proxy": "10.10.40.25"}) == {"no_proxy": "10.10.40.25"}


class TestUndeclaredKeysAreNeverExported:
    """A .env is the operator's own file and may hold anything.

    The first version of this filter was a denylist over the whole file, so a
    credential whose name missed the pattern would have been published into
    the environment the Ghidra JVM inherits.
    """

    @pytest.mark.parametrize(
        "key",
        [
            "MY_GITHUB_PAT",          # matches none of TOKEN|SECRET|PASSWORD|...
            "AWS_ACCESS_KEY_ID",      # an id, but still not ours to export
            "SENTINEL_NOT_A_SETTING",
            "EDITOR",
        ],
    )
    def test_an_undeclared_key_stays_out_of_the_environment(self, exported, key):
        assert exported({key: "whatever"}) == {key: None}

    def test_but_get_config_still_serves_it_in_process(self, monkeypatch):
        """Not exporting is not the same as not honouring.

        Anything in the file is still readable through get_config, which is
        how every in-process reader sees it. The export is only about what
        subprocesses and third-party libraries inherit.
        """
        monkeypatch.setattr(config_module, "_config_cache", {"MY_GITHUB_PAT": "ghp_x"})
        monkeypatch.setattr(config_module, "_env_loaded", True)
        monkeypatch.delenv("MY_GITHUB_PAT", raising=False)
        assert config_module.get_config("MY_GITHUB_PAT") == "ghp_x"


class TestCredentialsAreNeverExported:
    @pytest.mark.parametrize(
        "key",
        ["OBSIDIAN_AUTH_TOKEN", "BINARY_MCP_HTTP_TOKEN", "VT_API_KEY"],
    )
    def test_a_declared_credential_stays_in_the_cache(self, exported, key):
        """Declared, in CONFIG_KEYS, and still held back.

        runner.py:758 builds the Ghidra subprocess env from os.environ.copy(),
        and that JVM parses untrusted samples, so a bearer token here would be
        readable in /proc/<jvm>/environ for the length of a decompile.
        """
        assert key in CONFIG_KEYS, f"{key} should be a documented setting"
        assert exported({key: "a" * 64}) == {key: None}

    @pytest.mark.parametrize(
        "key", ["X64DBG_TLS_CLIENT_KEY", "BINARY_MCP_REMOTE_TLS_KEY"]
    )
    def test_a_path_to_a_private_key_stays_in_the_cache(self, exported, key):
        """The path is not the key, but it is a map to it.

        A sample with code execution in the JVM would otherwise read
        /proc/self/environ, learn where the private key lives, and open it as
        the same user. Nothing reads these off os.environ, so withholding them
        costs nothing.
        """
        assert exported({key: "/home/analyst/client.key"}) == {key: None}

    @pytest.mark.parametrize(
        "key",
        ["X64DBG_TLS_CA", "X64DBG_TLS_CLIENT_CERT", "BINARY_MCP_REMOTE_TLS_CERT"],
    )
    def test_public_tls_material_is_not_withheld(self, exported, key):
        """The counterpart: certificates and CAs are public, so they export.

        Without this the previous test could pass by withholding everything
        TLS-shaped, which would be a different bug.
        """
        assert exported({key: "/home/analyst/ca.pem"}) == {key: "/home/analyst/ca.pem"}


class TestPrecedence:
    def test_a_real_environment_variable_still_wins(self, exported):
        """The documented precedence: os.environ beats .env.

        Getting this backwards is what made a stale token in an MCP config
        silently override a corrected .env -- the bug that prompted the whole
        change.
        """
        result = exported(
            {"GHIDRA_MAX_HEAP_MB": "2048"}, preset={"GHIDRA_MAX_HEAP_MB": "8192"}
        )
        assert result == {"GHIDRA_MAX_HEAP_MB": "8192"}
