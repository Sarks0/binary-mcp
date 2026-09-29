"""
Regression tests for the VirusTotal integration (src/tools/vt_tools.py).

The module had never been exercised in production and had no tests of its own.
Each test below pins one behaviour that was wrong, or one API contract that a
future edit could silently break:

* hashes are validated as hex, not merely measured, before being spliced into
  a request path;
* VT epoch timestamps are rendered in UTC, not the server's local zone;
* the detection ratio matches the number VirusTotal itself displays;
* behaviour_summary fields whose entries are OBJECTS render as text rather
  than as a Python dict repr;
* the endpoint paths are the documented v3 ones.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.integrations import base as integration_base
from src.tools import vt_tools
from src.tools.vt_tools import (
    VirusTotalError,
    _utc_iso,
    _vt_error_detail,
    format_detection_summary,
    normalise_hash,
    render_observation,
)
from tests.integration_stubs import (
    FakeResponse,
    capture_requests,
    raise_http,
    shrink_response_cap,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture_requests(monkeypatch, payload: dict | None = None) -> list:
    """Record requests vt_tools builds, answering each with payload."""
    return capture_requests(
        monkeypatch, vt_tools._client,
        payload if payload is not None else {"data": {}},
        api_key="k" * 64,
    )


def _raise_http(monkeypatch, code, payload: dict | None = None) -> None:
    raise_http(monkeypatch, vt_tools._client, int(code), payload, api_key="k" * 64)


def _register(monkeypatch) -> dict:
    """Register the VT tools against a stub app and return them by name."""
    registered: dict[str, object] = {}
    app = MagicMock()

    def tool_decorator(*_args, **_kwargs):
        def _wrap(fn):
            registered[fn.__name__] = fn
            return fn
        return _wrap

    app.tool = MagicMock(side_effect=tool_decorator)
    vt_tools.register_vt_tools(app, MagicMock())
    return registered


# ---------------------------------------------------------------------------
# Hash validation: the argument is a hash, so enforce that
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("44d88612fea8a8f36de82e1278abb02f", "44d88612fea8a8f36de82e1278abb02f"),
        ("  44D88612FEA8A8F36DE82E1278ABB02F  ", "44d88612fea8a8f36de82e1278abb02f"),
        ("a" * 40, "a" * 40),
        ("F" * 64, "f" * 64),
    ],
)
def test_normalise_hash_accepts_md5_sha1_sha256(raw, expected):
    assert normalise_hash(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "a" * 31,
        "a" * 63,
        "z" * 32,                       # right length, not hex
        "a" * 30 + "/x",                # 32 chars, contains a path separator
        "a" * 28 + "?x=1",              # 32 chars, opens a query string
        "a" * 31 + "#",                 # 32 chars, opens a fragment
        "../" * 10 + "aa",              # 32 chars of traversal
        "a" * 32 + "\n" + "b" * 32,
    ],
)
def test_normalise_hash_rejects_non_hash_values(raw):
    """
    The old check was ``len(h) not in (32, 40, 64)``.

    Every value here has an accepted LENGTH, so the old check passed it, and it
    was then interpolated into ``/files/{h}`` unescaped -- addressing a
    different path on VT's API, or appending query parameters to the one
    intended. Length is not validation.
    """
    with pytest.raises(ValueError):
        normalise_hash(raw)


def test_lookup_hash_refuses_a_path_injecting_hash(monkeypatch):
    seen = _capture_requests(monkeypatch)
    with pytest.raises(ValueError):
        vt_tools.lookup_hash("a" * 30 + "/x")
    assert seen == [], "a rejected hash must not reach the network"


def test_behaviour_report_refuses_a_path_injecting_hash(monkeypatch):
    seen = _capture_requests(monkeypatch)
    with pytest.raises(ValueError):
        vt_tools.get_behavior_report("../" * 10 + "aa")
    assert seen == []


# ---------------------------------------------------------------------------
# Endpoint contracts
# ---------------------------------------------------------------------------


def test_lookup_hash_calls_the_documented_file_endpoint(monkeypatch):
    seen = _capture_requests(monkeypatch, {"data": {"attributes": {}}})
    vt_tools.lookup_hash("a" * 64)
    assert seen[0].full_url == f"https://www.virustotal.com/api/v3/files/{'a' * 64}"
    assert seen[0].get_method() == "GET"
    assert seen[0].headers["X-apikey"] == "k" * 64


def test_behaviour_report_calls_the_documented_summary_endpoint(monkeypatch):
    seen = _capture_requests(monkeypatch, {"data": {}})
    vt_tools.get_behavior_report("b" * 64)
    assert seen[0].full_url == (
        f"https://www.virustotal.com/api/v3/files/{'b' * 64}/behaviour_summary"
    )


def test_search_encodes_the_query_and_clamps_the_limit(monkeypatch):
    seen = _capture_requests(monkeypatch, {"data": [], "meta": {}})

    vt_tools.search_files("tag:ransomware p:5+", limit=9999)

    url = seen[0].full_url
    assert url.startswith("https://www.virustotal.com/api/v3/intelligence/search?")
    # ':' and '+' are meaningful in a query string and must not survive raw.
    assert "tag%3Aransomware" in url
    assert "p%3A5%2B" in url
    assert f"limit={vt_tools.VT_SEARCH_MAX_LIMIT}" in url


def test_search_floors_the_limit_at_one(monkeypatch):
    seen = _capture_requests(monkeypatch, {"data": [], "meta": {}})
    vt_tools.search_files("tag:x", limit=0)
    assert "limit=1" in seen[0].full_url


def test_search_returns_and_forwards_the_cursor(monkeypatch):
    seen = _capture_requests(
        monkeypatch, {"data": [{"attributes": {}}], "meta": {"cursor": "NEXT=="}}
    )

    results, cursor = vt_tools.search_files("tag:x", limit=10)
    assert len(results) == 1
    assert cursor == "NEXT=="

    vt_tools.search_files("tag:x", limit=10, cursor="NEXT==")
    assert "cursor=NEXT%3D%3D" in seen[1].full_url


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------


def test_timestamps_are_rendered_in_utc_regardless_of_server_zone(monkeypatch):
    """
    VT epoch timestamps are UTC. ``datetime.fromtimestamp()`` without tzinfo
    reinterprets them in the server's local zone and prints no offset, so the
    same report read differently in London and California with nothing in the
    output to say which. Pin the offset.
    """
    import time

    monkeypatch.setenv("TZ", "America/Los_Angeles")
    if hasattr(time, "tzset"):
        time.tzset()
    try:
        assert _utc_iso(1700000000) == "2023-11-14T22:13:20+00:00"
    finally:
        monkeypatch.delenv("TZ", raising=False)
        if hasattr(time, "tzset"):
            time.tzset()


@pytest.mark.parametrize("bad", [None, "not-a-number", object()])
def test_utc_iso_degrades_to_none_on_junk(bad):
    assert _utc_iso(bad) is None


def test_summary_timestamps_carry_an_explicit_offset():
    summary = format_detection_summary(
        {"attributes": {"first_submission_date": 1700000000,
                        "last_submission_date": 1700000001,
                        "last_analysis_date": 1700000002}}
    )
    for field in ("first_seen", "last_seen", "last_analysis"):
        assert summary[field].endswith("+00:00"), field


# ---------------------------------------------------------------------------
# Detection ratio
# ---------------------------------------------------------------------------


def test_detection_ratio_matches_virustotals_own_convention():
    """
    VT shows malicious over the engines that returned a verdict.

    The old code reported ``(malicious + suspicious) / sum(stats.values())``,
    which is wrong in both halves: it folded 'suspicious' into the numerator
    and counted engines that never looked at the file in the denominator.
    """
    summary = format_detection_summary(
        {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 2,
                    "undetected": 15,
                    "harmless": 0,
                    "timeout": 0,
                    "confirmed-timeout": 0,
                    "failure": 1,
                    "type-unsupported": 7,
                },
            }
        }
    )

    assert summary["detection_ratio"] == "45/62"   # 70 total - 7 unsupported - 1 failure
    assert summary["total_engines"] == 70
    assert summary["scanned_engines"] == 62
    assert summary["flagged"] == 47


def test_detection_ratio_survives_missing_and_junk_stats():
    summary = format_detection_summary({"attributes": {"last_analysis_stats": {}}})
    assert summary["detection_ratio"] == "0/0"

    summary = format_detection_summary(
        {"attributes": {"last_analysis_stats": {"malicious": "3", "undetected": None}}}
    )
    assert summary["malicious"] == 3
    assert summary["scanned_engines"] == 3


def test_summary_skips_engine_results_that_are_not_objects():
    summary = format_detection_summary(
        {
            "attributes": {
                "last_analysis_results": {
                    "GoodEngine": {"category": "malicious", "result": "Trojan.X"},
                    "BrokenEngine": "malicious",
                }
            }
        }
    )
    assert [d["engine"] for d in summary["detections"]] == ["GoodEngine"]


# ---------------------------------------------------------------------------
# Behaviour rendering: object-valued fields
# ---------------------------------------------------------------------------


def test_registry_keys_set_renders_as_text_not_a_dict_repr():
    line = render_observation(
        {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "value": "C:\\Users\\v\\AppData\\x.exe"},
        ("key", "value"),
    )
    assert line == (
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | "
        "C:\\Users\\v\\AppData\\x.exe"
    )
    assert "{" not in line and "'" not in line


def test_unrecognised_object_falls_back_to_json_not_repr():
    line = render_observation({"unexpected_field": "value"}, ("path",))
    assert line == '{"unexpected_field": "value"}'


def test_short_observations_are_not_marked_as_truncated():
    """``f"  - {c[:100]}..."`` claimed every command line was cut short."""
    assert render_observation("cmd.exe /c whoami") == "cmd.exe /c whoami"


def test_long_observations_say_how_long_they_really_were():
    line = render_observation("A" * 500)
    assert line.startswith("A" * 300)
    assert "[truncated, 500 chars]" in line


def test_newlines_in_an_observation_do_not_break_the_line_format():
    assert "\n" not in render_observation("cmd.exe\n/c\rwhoami")


def test_vt_behavior_renders_object_fields_and_the_new_sections(monkeypatch):
    monkeypatch.setattr(
        vt_tools,
        "get_behavior_report",
        lambda h: {
            "registry_keys_set": [{"key": "HKCU\\Run\\svc", "value": "evil.exe"}],
            "files_dropped": [{"path": "C:\\t\\a.dll", "sha256": "f" * 64}],
            "ip_traffic": [{"destination_ip": "10.0.0.5", "destination_port": 443,
                            "transport_layer_protocol": "tcp"}],
            "processes_injected": ["explorer.exe"],
            "modules_loaded": ["ntdll.dll"],
            "mitre_attack_techniques": [{"id": "T1547.001",
                                         "signature_description": "Registry Run key"}],
        },
    )

    out = _register(monkeypatch)["vt_behavior"]("e" * 64)

    assert "HKCU\\Run\\svc | evil.exe" in out
    assert "{'key'" not in out, "a Python dict repr reached the report"
    assert "C:\\t\\a.dll | " + "f" * 64 in out
    assert "10.0.0.5 | 443 | tcp" in out
    assert "Processes Injected (1):" in out
    assert "Modules Loaded (1):" in out
    assert "T1547.001 | Registry Run key" in out


def test_vt_behavior_reports_an_empty_summary_plainly(monkeypatch):
    monkeypatch.setattr(vt_tools, "get_behavior_report", lambda h: {"tags": []})
    out = _register(monkeypatch)["vt_behavior"]("e" * 64)
    assert "No significant behavior recorded." in out


def test_vt_behavior_rejects_a_malformed_hash_before_calling_out(monkeypatch):
    seen = _capture_requests(monkeypatch)
    out = _register(monkeypatch)["vt_behavior"]("nope")
    assert "Invalid hash" in out
    assert seen == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_vt_error_detail_extracts_virustotals_own_sentence():
    body = json.dumps(
        {"error": {"code": "ForbiddenError", "message": "You are not authorized"}}
    ).encode()
    assert _vt_error_detail(body) == "ForbiddenError: You are not authorized"


def test_vt_error_detail_is_single_line_and_capped():
    body = json.dumps({"error": {"message": "a\nb" + "c" * 1000}}).encode()
    detail = _vt_error_detail(body)
    assert "\n" not in detail
    assert len(detail) <= 300


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"{}"])
def test_vt_error_detail_tolerates_a_non_conforming_body(body):
    assert _vt_error_detail(body) == ""


def test_premium_only_endpoint_reports_a_missing_privilege(monkeypatch):
    """
    /intelligence/search is Enterprise-only; a public key gets 403.

    The old code answered "VirusTotal API error: 403 Forbidden", which reads
    like an outage. Say what it actually is.
    """
    _raise_http(monkeypatch, 403, {"error": {"code": "ForbiddenError",
                                             "message": "not enough privileges"}})
    with pytest.raises(VirusTotalError) as excinfo:
        vt_tools.search_files("tag:ransomware")
    message = str(excinfo.value)
    assert "privilege" in message
    assert "not enough privileges" in message


def test_rate_limit_message_states_the_public_api_budget(monkeypatch):
    _raise_http(monkeypatch, 429)
    with pytest.raises(VirusTotalError) as excinfo:
        vt_tools.lookup_hash("a" * 64)
    assert "4 requests/minute" in str(excinfo.value)


def test_missing_hash_still_reports_not_found(monkeypatch):
    _raise_http(monkeypatch, 404)
    with pytest.raises(VirusTotalError, match="not found"):
        vt_tools.lookup_hash("a" * 64)


def test_oversize_response_is_refused(monkeypatch):
    _capture_requests(monkeypatch)
    shrink_response_cap(monkeypatch, vt_tools._client, 16)
    monkeypatch.setattr(
        integration_base, "urlopen", lambda req, timeout=None: FakeResponse(b"x" * 64)
    )
    with pytest.raises(VirusTotalError, match="response cap"):
        vt_tools.lookup_hash("a" * 64)


def test_non_json_response_is_reported_as_such(monkeypatch):
    _capture_requests(monkeypatch)
    monkeypatch.setattr(
        integration_base,
        "urlopen",
        lambda req, timeout=None: FakeResponse(b"<html>502</html>"),
    )
    with pytest.raises(VirusTotalError, match="not JSON"):
        vt_tools.lookup_hash("a" * 64)


# ---------------------------------------------------------------------------
# API key handling
# ---------------------------------------------------------------------------


def test_check_api_masks_the_key_and_never_prints_it_whole(monkeypatch):
    key = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(vt_tools, "_get_api_key", lambda: key)
    monkeypatch.setattr(
        vt_tools, "lookup_hash",
        lambda h: {"attributes": {"last_analysis_stats": {"malicious": 60,
                                                          "undetected": 10}}},
    )
    monkeypatch.setattr(vt_tools, "_quota_lines", lambda: ["Quota:", "  Daily: 3 used of 500"])

    out = _register(monkeypatch)["vt_check_api"]()

    assert key not in out
    assert "0123...cdef" in out
    assert "Daily: 3 used of 500" in out


def test_quota_failure_never_surfaces_the_url_that_carries_the_key(monkeypatch):
    """
    /users/{id}/overall_quotas puts the API key in the request path, so a
    urllib error string for that call can quote the key. Summarise, never
    surface.
    """
    key = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(vt_tools, "_get_api_key", lambda: key)

    def boom(*_args, **_kwargs):
        raise VirusTotalError(f"Network error connecting to https://x/users/{key}/overall_quotas")

    monkeypatch.setattr(vt_tools, "_vt_request", boom)

    lines = vt_tools._quota_lines()
    assert lines == ["Quota: not reported (the key may not have access to this endpoint)"]
    assert key not in "\n".join(lines)


def test_quota_lines_render_used_and_allowed(monkeypatch):
    monkeypatch.setattr(vt_tools, "_get_api_key", lambda: "k" * 64)
    monkeypatch.setattr(
        vt_tools,
        "_vt_request",
        lambda *a, **k: {
            "data": {
                "api_requests_daily": {"user": {"used": 12, "allowed": 500}},
                "api_requests_hourly": {"user": {"used": 1, "allowed": 240}},
            }
        },
    )
    lines = vt_tools._quota_lines()
    assert "  Daily: 12 used of 500" in lines
    assert "  Hourly: 1 used of 240" in lines


def test_missing_api_key_is_a_configuration_error_not_a_crash(monkeypatch):
    monkeypatch.setattr(vt_tools, "_get_api_key", lambda: None)
    out = _register(monkeypatch)["vt_lookup"](file_hash="a" * 64)
    assert "not configured" in out
