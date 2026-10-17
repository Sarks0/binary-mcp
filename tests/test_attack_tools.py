"""
Tests for the MITRE ATT&CK integration.

ATT&CK differs from the other providers in three ways that need their own
assertions: there is no API key, the useful work is a DISTILLATION of a 51MB
STIX bundle rather than a request/response, and the result is cached so that
every call after the first touches no network at all.

The bundle fixture below is small but structurally faithful -- external
references, kill-chain phases, STIX-UUID relationships, a deprecated entry and
objects that must be dropped -- so the distillation is tested against the shape
the real data actually has.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from src.integrations import base as integration_base
from src.tools import attack_tools
from src.tools.attack_tools import (
    AttackDataError,
    AttackFetchPending,
    distil,
    related,
    resolve,
)
from tests.integration_stubs import capture_requests

# STIX UUIDs, referenced by the relationships below.
_T_INJECT = "attack-pattern--1111"
_T_DLL = "attack-pattern--2222"
_T_OLD = "attack-pattern--3333"
_G_APT = "intrusion-set--4444"
_S_MAL = "malware--5555"
_TOOL = "tool--6666"
_C_CAMP = "campaign--7777"


def _bundle() -> dict:
    return {
        "type": "bundle",
        "objects": [
            # Tactic definitions -- the source of truth for phase labels.
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--a",
             "x_mitre_shortname": "stealth", "name": "Stealth"},
            {"type": "x-mitre-tactic", "id": "x-mitre-tactic--b",
             "x_mitre_shortname": "privilege-escalation",
             "name": "Privilege Escalation"},

            {"type": "attack-pattern", "id": _T_INJECT, "name": "Process Injection",
             "description": "Adversaries may inject code into processes.",
             "external_references": [
                 {"source_name": "mitre-attack", "external_id": "T1055",
                  "url": "https://attack.mitre.org/techniques/T1055"},
                 {"source_name": "Some Vendor", "external_id": "IGNORED"},
             ],
             "kill_chain_phases": [
                 {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                 {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
                 {"kill_chain_name": "other-chain", "phase_name": "not-attack"},
             ],
             "x_mitre_platforms": ["Windows", "Linux"],
             "x_mitre_is_subtechnique": False},

            {"type": "attack-pattern", "id": _T_DLL, "name": "DLL Injection",
             "description": "A sub-technique.",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "T1055.001"}],
             "x_mitre_is_subtechnique": True},

            {"type": "attack-pattern", "id": _T_OLD, "name": "Retired Thing",
             "description": "No longer current.",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "T1064"}],
             "x_mitre_deprecated": True},

            {"type": "intrusion-set", "id": _G_APT, "name": "APT38",
             # Mentions "injection" in prose only -- the techniques match the
             # same term by NAME, which is what makes the ranking observable.
             "description": "A group that favours process injection.",
             "aliases": ["APT38", "Bluenoroff", "Stardust Chollima"],
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "G0082"}]},

            {"type": "malware", "id": _S_MAL, "name": "Cobalt Strike",
             "description": "A family.", "x_mitre_aliases": ["Cobalt Strike", "CS"],
             "x_mitre_platforms": ["Windows"],
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "S0154"}]},

            {"type": "tool", "id": _TOOL, "name": "PsExec",
             "description": "A tool.",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "S0029"}]},

            {"type": "campaign", "id": _C_CAMP, "name": "Operation Test",
             "description": "A campaign.",
             "external_references": [{"source_name": "mitre-attack",
                                      "external_id": "C0023"}]},

            # An entity with no mitre-attack reference must be dropped.
            {"type": "malware", "id": "malware--9999", "name": "Unlisted",
             "external_references": [{"source_name": "Vendor", "external_id": "X1"}]},

            # Object types the distillation drops entirely.
            {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a", "name": "noise"},
            {"type": "x-mitre-data-component", "id": "x-mitre-data-component--a",
             "name": "noise"},
            {"type": "identity", "id": "identity--a", "name": "The MITRE Corporation"},

            {"type": "relationship", "id": "relationship--a",
             "relationship_type": "subtechnique-of",
             "source_ref": _T_DLL, "target_ref": _T_INJECT},
            {"type": "relationship", "id": "relationship--b",
             "relationship_type": "uses", "source_ref": _G_APT, "target_ref": _T_INJECT},
            {"type": "relationship", "id": "relationship--c",
             "relationship_type": "uses", "source_ref": _G_APT, "target_ref": _S_MAL},
            {"type": "relationship", "id": "relationship--d",
             "relationship_type": "uses", "source_ref": _S_MAL, "target_ref": _T_INJECT},
            {"type": "relationship", "id": "relationship--e",
             "relationship_type": "uses", "source_ref": _TOOL, "target_ref": _T_INJECT},
            {"type": "relationship", "id": "relationship--f",
             "relationship_type": "attributed-to",
             "source_ref": _C_CAMP, "target_ref": _G_APT},
            # Dangling: one end is an object that was dropped.
            {"type": "relationship", "id": "relationship--g",
             "relationship_type": "uses",
             "source_ref": "malware--9999", "target_ref": _T_INJECT},
        ],
    }


@pytest.fixture
def index() -> dict:
    return distil(_bundle(), "19.2")


@pytest.fixture
def cached(tmp_path, monkeypatch, index) -> dict:
    """A populated on-disk cache, with the network stubbed to fail loudly."""
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path))
    path = attack_tools.index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index), encoding="utf-8")

    def no_network(*_args, **_kwargs):
        raise AssertionError("a cached lookup reached the network")

    monkeypatch.setattr(integration_base, "urlopen", no_network)
    return index


def _tools(monkeypatch) -> dict:
    registered: dict[str, object] = {}
    app = MagicMock()

    def tool_decorator(*_args, **_kwargs):
        def _wrap(fn):
            registered[fn.__name__] = fn
            return fn
        return _wrap

    app.tool = MagicMock(side_effect=tool_decorator)
    attack_tools.register_attack_tools(app, MagicMock())
    return registered


# Distillation


def test_distil_keeps_only_the_entities_these_tools_answer_with(index):
    assert set(index["entities"]) == {
        "T1055", "T1055.001", "T1064", "G0082", "S0154", "S0029", "C0023"
    }


def test_distil_drops_entities_with_no_attack_id(index):
    """An object without a mitre-attack reference has no ID to address it by."""
    assert not any(e["name"] == "Unlisted" for e in index["entities"].values())


def test_tactic_labels_come_from_the_bundle_not_a_hardcoded_table(index):
    """
    ATT&CK renames tactics between versions -- v19 files T1055 under "stealth"
    where earlier releases said "defense-evasion". A hardcoded map would
    silently mislabel techniques after an upgrade.
    """
    assert index["tactics"] == {
        "stealth": "Stealth", "privilege-escalation": "Privilege Escalation"
    }
    assert index["entities"]["T1055"]["tactics"] == ["Stealth", "Privilege Escalation"]


def test_only_mitre_attack_kill_chain_phases_count(index):
    assert "not-attack" not in index["entities"]["T1055"]["tactics"]


def test_only_the_mitre_attack_external_reference_is_used(index):
    assert index["entities"]["T1055"]["id"] == "T1055"
    assert "IGNORED" not in index["entities"]


def test_relationships_are_resolved_to_attack_ids(index):
    """STIX UUIDs are resolved here so nothing downstream carries two id spaces."""
    assert ["uses", "G0082", "T1055"] in index["relationships"]
    assert ["subtechnique-of", "T1055.001", "T1055"] in index["relationships"]
    assert not any("--" in part for rel in index["relationships"] for part in rel[1:])


def test_relationships_to_dropped_objects_are_discarded(index):
    assert all("malware--9999" not in rel for rel in index["relationships"])
    assert len(index["relationships"]) == 6


def test_deprecated_entries_are_flagged_not_dropped(index):
    """
    An old report citing T1064 should still resolve, with a note, rather than
    coming back "unknown".
    """
    assert index["entities"]["T1064"]["retired"] is True
    assert index["entities"]["T1055"]["retired"] is False


def test_aliases_come_from_either_stix_spelling(index):
    assert "Bluenoroff" in index["entities"]["G0082"]["aliases"]
    assert "CS" in index["entities"]["S0154"]["aliases"]


def test_version_is_recorded(index):
    assert index["attack_version"] == "19.2"


# Resolution


def test_resolve_by_id_name_and_alias(index):
    assert resolve(index, "T1055")["name"] == "Process Injection"
    assert resolve(index, "t1055")["id"] == "T1055"
    assert resolve(index, "Process Injection")["id"] == "T1055"
    assert resolve(index, "process injection")["id"] == "T1055"
    assert resolve(index, "Bluenoroff")["id"] == "G0082"
    assert resolve(index, "bluenoroff")["id"] == "G0082"


def test_resolve_honours_the_kind_filter(index):
    assert resolve(index, "T1055", kinds=("intrusion-set",)) is None
    assert resolve(index, "G0082", kinds=("intrusion-set",))["id"] == "G0082"
    assert resolve(index, "PsExec", kinds=("malware", "tool"))["id"] == "S0029"


def test_resolve_prefers_an_exact_name_over_an_alias(index):
    """Both exist in ATT&CK; the primary name is the less surprising answer."""
    assert resolve(index, "APT38")["id"] == "G0082"


def test_resolve_returns_none_for_nothing(index):
    assert resolve(index, "") is None
    assert resolve(index, "   ") is None
    assert resolve(index, "no such thing") is None


# Relationship traversal


def test_related_follows_both_directions(index):
    assert [e["id"] for e in related(index, "G0082", "uses")] == ["S0154", "T1055"]
    users = related(index, "T1055", "uses", as_source=False)
    assert [e["id"] for e in users] == ["G0082", "S0029", "S0154"]


def test_related_filters_by_kind(index):
    groups = related(index, "T1055", "uses", as_source=False, kinds=("intrusion-set",))
    assert [e["id"] for e in groups] == ["G0082"]
    software = related(index, "T1055", "uses", as_source=False,
                       kinds=("malware", "tool"))
    assert [e["id"] for e in software] == ["S0029", "S0154"]


def test_related_distinguishes_relationship_types(index):
    assert [e["id"] for e in related(index, "T1055", "subtechnique-of",
                                     as_source=False)] == ["T1055.001"]
    assert related(index, "T1055", "mitigates") == []


# Caching: no key, and no network after the first fetch


def test_attack_needs_no_api_key():
    assert attack_tools.client.config.key_config_keys == ()
    assert attack_tools.client.require_key() == ""


def test_no_auth_header_is_sent(monkeypatch, tmp_path):
    seen = capture_requests(monkeypatch, attack_tools.client, {}, api_key="")
    attack_tools.client.request("index.json")
    assert "Authorization" not in seen[0].headers
    assert not any(k.lower().endswith("key") for k in seen[0].headers)


def test_a_cached_index_is_served_without_touching_the_network(cached):
    """The whole point of distilling: every call after the first is offline."""
    index = attack_tools.load_index()
    assert index["entities"]["T1055"]["name"] == "Process Injection"


def test_every_lookup_tool_works_from_cache(cached, monkeypatch):
    tools = _tools(monkeypatch)
    assert "Process Injection" in tools["attack_lookup_technique"]("T1055")
    assert "APT38" in tools["attack_lookup_group"]("Bluenoroff")
    assert "Cobalt Strike" in tools["attack_lookup_software"]("S0154")
    assert "T1055" in tools["attack_search"]("injection")


def test_offline_without_a_cache_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path / "empty"))
    monkeypatch.setenv("ATTACK_OFFLINE", "1")
    with pytest.raises(AttackDataError, match="ATTACK_OFFLINE"):
        attack_tools.load_index()


def test_a_corrupt_cache_is_refetched_rather_than_raised(tmp_path, monkeypatch, index):
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path))
    path = attack_tools.index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ this is not json", encoding="utf-8")
    monkeypatch.setattr(attack_tools, "fetch_index", lambda matrix=None: index)

    assert attack_tools.load_index()["entities"]["T1055"]["name"] == "Process Injection"
    # ...and the good data replaces the corrupt file.
    assert json.loads(path.read_text())["entities"]["T1055"]


def test_refresh_refetches_even_with_a_cache(cached, monkeypatch):
    calls = []

    def fake_fetch(matrix=None):
        calls.append(matrix)
        return {"attack_version": "99.9", "tactics": {}, "entities": {},
                "relationships": []}

    monkeypatch.setattr(attack_tools, "fetch_index", fake_fetch)
    assert attack_tools.load_index(refresh=True)["attack_version"] == "99.9"
    assert calls


# Fetching


def _catalogue(url: str) -> dict:
    return {"collections": [{"name": "Enterprise ATT&CK",
                             "versions": [{"version": "19.2", "url": url}]}]}


def _serve(monkeypatch, *bodies: dict) -> list:
    """Answer successive requests with successive bodies, recording each."""
    from tests.integration_stubs import FakeResponse

    seen: list = []
    queued = [json.dumps(body).encode() for body in bodies]

    def fake_urlopen(request, timeout=None):
        seen.append(request)
        return FakeResponse(queued.pop(0))

    monkeypatch.setattr(attack_tools.client, "api_key", lambda: "")
    monkeypatch.setattr(integration_base, "urlopen", fake_urlopen)
    return seen


def test_fetch_resolves_the_matrix_through_the_collection_index(monkeypatch):
    bundle_url = attack_tools.ATTACK_INDEX_URL_BASE + \
        "enterprise-attack/enterprise-attack-19.2.json"
    seen = _serve(monkeypatch, _catalogue(bundle_url), _bundle())

    index = attack_tools.fetch_index("enterprise-attack")

    assert seen[0].full_url == attack_tools.ATTACK_INDEX_URL_BASE + "index.json"
    assert seen[1].full_url == bundle_url
    assert index["attack_version"] == "19.2"
    assert index["entities"]["T1055"]["name"] == "Process Injection"


def test_a_matrix_absent_from_the_index_is_reported(monkeypatch):
    capture_requests(
        monkeypatch, attack_tools.client,
        _catalogue(attack_tools.ATTACK_INDEX_URL_BASE + "ics-attack/ics-attack-19.2.json"),
        api_key="",
    )
    with pytest.raises(AttackDataError, match="no bundle for enterprise-attack"):
        attack_tools.fetch_index("enterprise-attack")


def test_an_index_pointing_off_host_is_refused(monkeypatch):
    """
    The bundle URL comes from a downloaded file. Following it blindly would let
    whatever served that file choose the next host this server fetches from.
    """
    capture_requests(
        monkeypatch, attack_tools.client,
        _catalogue("https://elsewhere.test/enterprise-attack/evil.json"),
        api_key="",
    )
    with pytest.raises(AttackDataError, match="pointed somewhere unexpected"):
        attack_tools.fetch_index("enterprise-attack")


def test_an_empty_bundle_is_reported(monkeypatch):
    bundle_url = attack_tools.ATTACK_INDEX_URL_BASE + "enterprise-attack/x.json"
    _serve(monkeypatch, _catalogue(bundle_url), {"type": "bundle", "objects": []})
    with pytest.raises(AttackDataError, match="no objects"):
        attack_tools.fetch_index("enterprise-attack")


# Tool behaviour


def test_status_reports_version_and_counts(cached, monkeypatch):
    out = _tools(monkeypatch)["attack_status"]()
    assert "19.2" in out
    assert "enterprise-attack" in out
    assert "Technique: 3" in out
    assert "Relationships: 6" in out


def test_technique_lookup_lists_its_users_and_subtechniques(cached, monkeypatch):
    out = _tools(monkeypatch)["attack_lookup_technique"]("T1055")
    assert "Tactics: Stealth, Privilege Escalation" in out
    assert "Platforms: Windows, Linux" in out
    assert "Sub-techniques (1):" in out and "T1055.001" in out
    assert "Used by groups (1):" in out and "G0082" in out
    assert "Used by software (2):" in out


def test_a_subtechnique_names_its_parent(cached, monkeypatch):
    out = _tools(monkeypatch)["attack_lookup_technique"]("T1055.001")
    assert "Sub-technique of: T1055 Process Injection" in out


def test_a_retired_technique_still_resolves_with_a_note(cached, monkeypatch):
    out = _tools(monkeypatch)["attack_lookup_technique"]("T1064")
    assert "T1064" in out
    assert "deprecated or revoked" in out


def test_group_lookup_separates_software_from_techniques(cached, monkeypatch):
    out = _tools(monkeypatch)["attack_lookup_group"]("APT38")
    assert "Also known as: Bluenoroff, Stardust Chollima" in out
    assert "Software used (1):" in out and "S0154" in out
    assert "Techniques used (1):" in out and "T1055" in out
    assert "Attributed campaigns (1):" in out and "C0023" in out


def test_looking_up_the_wrong_kind_is_a_miss_not_a_wrong_answer(cached, monkeypatch):
    tools = _tools(monkeypatch)
    assert "No ATT&CK group matched" in tools["attack_lookup_group"]("T1055")
    assert "No ATT&CK software matched" in tools["attack_lookup_software"]("G0082")
    assert "No ATT&CK technique matched" in tools["attack_lookup_technique"]("G0082")


def test_search_ranks_name_hits_above_description_hits(cached, monkeypatch):
    """
    Two techniques carry "injection" in their NAME; the group carries it only
    in its description. A specific term should rank above a passing mention.
    """
    out = _tools(monkeypatch)["attack_search"]("injection")
    body = out[out.index("Found"):]

    assert "2 by name or alias" in body
    assert body.index("T1055 ") < body.index("G0082"), (
        "a description-only hit outranked a name hit"
    )
    assert body.index("T1055.001") < body.index("G0082")


def test_search_scope_filters_by_kind(cached, monkeypatch):
    tools = _tools(monkeypatch)
    assert "G0082" in tools["attack_search"]("a", kind="group")
    assert "T1055" not in tools["attack_search"]("a", kind="group")


def test_search_rejects_an_unknown_scope(cached, monkeypatch):
    assert "kind must be one of" in _tools(monkeypatch)["attack_search"]("x", kind="nope")


def test_search_clamps_the_limit(cached, monkeypatch):
    tools = _tools(monkeypatch)
    assert "Found" in tools["attack_search"]("a", limit=99999)
    assert "limit must be an integer" in tools["attack_search"]("a", limit="lots")


def test_search_requires_a_term(cached, monkeypatch):
    assert "Provide a search term" in _tools(monkeypatch)["attack_search"]("  ")


def test_a_long_description_is_truncated_with_its_real_length(cached, monkeypatch,
                                                              tmp_path, index):
    index["entities"]["T1055"]["description"] = "x" * 5000
    attack_tools.index_path().write_text(json.dumps(index), encoding="utf-8")
    out = _tools(monkeypatch)["attack_lookup_technique"]("T1055")
    assert "truncated, 5000 characters total" in out


def test_the_configured_matrix_is_honoured(monkeypatch):
    monkeypatch.setenv("ATTACK_DOMAIN", "ics-attack")
    assert attack_tools.domain() == "ics-attack"
    assert attack_tools.index_path().name == "ics-attack-index.json"


def test_an_unknown_matrix_falls_back_to_enterprise(monkeypatch):
    monkeypatch.setenv("ATTACK_DOMAIN", "not-a-matrix")
    assert attack_tools.domain() == "enterprise-attack"


def test_offline_refresh_against_a_populated_cache_says_what_is_true(cached, monkeypatch):
    """
    The single old message claimed "No cached ATT&CK data" and advised unsetting
    the air-gap setting. With a cache present that is false on both counts.
    """
    monkeypatch.setenv("ATTACK_OFFLINE", "1")
    with pytest.raises(AttackDataError) as excinfo:
        attack_tools.load_index(refresh=True)
    message = str(excinfo.value)
    assert "cannot be refreshed" in message
    assert "No cached ATT&CK data" not in message
    assert "Unset it once" not in message


def test_the_cache_is_written_atomically(tmp_path, monkeypatch, index):
    """
    A plain write_text leaves a reader parsing a half-written 2.7MB file, which
    reads as corrupt and sends it back to the network. The swap must be atomic,
    so no .tmp file survives and the final path is complete JSON.
    """
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(attack_tools, "fetch_index", lambda matrix=None: index)

    attack_tools.load_index()

    cached = attack_tools.index_path()
    assert json.loads(cached.read_text())["entities"]["T1055"]
    assert not list(tmp_path.glob("*.tmp")), "a temporary file was left behind"


def test_a_second_caller_waits_and_reuses_the_first_fetch(tmp_path, monkeypatch, index):
    """
    Two cold-cache callers must not each download the bundle. The lock makes the
    second wait; it then finds the cache populated and fetches nothing.
    """
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path))
    fetches = []

    def counting_fetch(matrix=None):
        fetches.append(matrix)
        return index

    monkeypatch.setattr(attack_tools, "fetch_index", counting_fetch)

    attack_tools.load_index()
    attack_tools.load_index()
    assert len(fetches) == 1, "the second caller re-downloaded the bundle"


def test_a_held_lock_still_answers_rather_than_failing(tmp_path, monkeypatch, index):
    """A stuck downloader must not turn every lookup into an error."""
    monkeypatch.setenv("ATTACK_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(attack_tools, "fetch_index", lambda matrix=None: index)

    def always_timeout(*_args, **_kwargs):
        raise attack_tools.LockTimeoutError("held")

    monkeypatch.setattr(attack_tools, "exclusive_lock", always_timeout)
    assert attack_tools.load_index()["entities"]["T1055"]["name"] == "Process Injection"


# The cold fetch, and not blocking the caller through it


class _FakeRegistry:
    """Enough of JobRegistry for the degrade path, recording what it was asked.

    It calls ``fn(context)``, because the real registry does (jobs.py ``_run``)
    -- an earlier version of this fake called ``fn()`` and every test here
    passed while the real path raised TypeError inside the job on the first
    cold fetch. A fake that is easier to satisfy than the thing it stands in
    for tests nothing.
    """

    def __init__(self, state, *, run=True, error=None, submit_error=None):
        self.state = state
        self.run = run
        self.error = error
        self.submit_error = submit_error
        self.submitted = []
        self.waited = []

    def submit(self, *, kind, key, fn):
        self.submitted.append((kind, key))
        if self.submit_error:
            return {"error": self.submit_error}
        if self.run:
            fn(MagicMock())
        return {"job_id": "job-1", "state": self.state, "attached": False}

    def wait(self, job_id, timeout):
        self.waited.append((job_id, timeout))
        if self.state is None:
            return None
        return {"state": self.state, "error": self.error}


@pytest.fixture(autouse=True)
def _no_registry_by_default(monkeypatch):
    """Every test starts as a plain library: no registry unless it asks for one."""
    monkeypatch.setattr(attack_tools, "_job_degrade", None)


def _with_server(monkeypatch, registry, deadline=25.0):
    """Wire the registry in the way the server does at startup."""
    monkeypatch.setattr(attack_tools, "_job_degrade", (registry, lambda: deadline))


def _cold_cache(monkeypatch, tmp_path, bundle_index):
    """A data dir with no cached index, and a fetch that returns bundle_index."""
    monkeypatch.setattr(attack_tools, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(attack_tools, "fetch_index", lambda matrix=None: bundle_index)


def test_a_cold_fetch_runs_inline_when_no_server_is_driving(monkeypatch, tmp_path, index):
    """As a plain library there is no registry and nobody to poll a handle."""
    assert attack_tools._job_degrade is None  # the autouse fixture's doing
    _cold_cache(monkeypatch, tmp_path, index)

    loaded = attack_tools.load_index("enterprise-attack")

    assert loaded["entities"] == index["entities"]
    assert (tmp_path / "enterprise-attack-index.json").exists()


def test_a_cold_fetch_is_submitted_as_a_job_when_the_server_is(monkeypatch, tmp_path, index):
    registry = _FakeRegistry("succeeded")
    _with_server(monkeypatch, registry, deadline=25.0)
    _cold_cache(monkeypatch, tmp_path, index)

    loaded = attack_tools.load_index("enterprise-attack")

    assert registry.submitted == [("attack-index", "attack-index:enterprise-attack")]
    assert registry.waited == [("job-1", 25.0)]
    assert loaded["entities"] == index["entities"]


def test_a_download_past_the_deadline_hands_back_a_handle(monkeypatch, tmp_path, index):
    """The finding: ~51MB inline is long enough for a client to abandon the call."""
    registry = _FakeRegistry("running", run=False)
    _with_server(monkeypatch, registry, deadline=25.0)
    _cold_cache(monkeypatch, tmp_path, index)

    with pytest.raises(AttackFetchPending) as pending:
        attack_tools.load_index("enterprise-attack")

    message = str(pending.value)
    assert "job-1" in message
    assert "25s" in message
    assert "enterprise-attack" in message


def test_every_tool_returns_that_handle_rather_than_an_error(monkeypatch, tmp_path, index):
    registry = _FakeRegistry("running", run=False)
    _with_server(monkeypatch, registry, deadline=25.0)
    _cold_cache(monkeypatch, tmp_path, index)
    tools = _tools(monkeypatch)

    calls = {
        "attack_status": (),
        "attack_lookup_technique": ("T1055",),
        "attack_lookup_group": ("APT38",),
        "attack_lookup_software": ("Mimikatz",),
        "attack_search": ("inject",),
    }
    assert set(calls) == set(tools)

    for name, args in calls.items():
        out = tools[name](*args)
        assert "job_id: job-1" in out, name
        assert not out.startswith("Error"), name
        assert "ATT&CK error" not in out, name


@pytest.mark.parametrize("state", ["failed", "cancelled", "orphaned"])
def test_a_failed_download_is_still_an_error(monkeypatch, tmp_path, index, state):
    registry = _FakeRegistry(state, run=False, error="the network went away")
    _with_server(monkeypatch, registry, deadline=25.0)
    _cold_cache(monkeypatch, tmp_path, index)

    with pytest.raises(AttackDataError, match="the network went away"):
        attack_tools.load_index("enterprise-attack")


def test_a_refused_submit_is_an_error_not_a_handle(monkeypatch, tmp_path, index):
    registry = _FakeRegistry("running", run=False, submit_error="could not claim job key")
    _with_server(monkeypatch, registry, deadline=25.0)
    _cold_cache(monkeypatch, tmp_path, index)

    with pytest.raises(AttackDataError, match="could not claim job key"):
        attack_tools.load_index("enterprise-attack")


def test_a_warm_cache_never_reaches_the_registry(monkeypatch, tmp_path, index):
    """The fast path is the whole point: 99.99% of calls must not pay for this."""
    registry = _FakeRegistry("succeeded")
    _with_server(monkeypatch, registry)
    monkeypatch.setattr(attack_tools, "data_dir", lambda: tmp_path)
    (tmp_path / "enterprise-attack-index.json").write_text(json.dumps(index))

    loaded = attack_tools.load_index("enterprise-attack")

    assert registry.submitted == []
    assert loaded["entities"] == index["entities"]


def test_offline_still_refuses_before_any_job_is_submitted(monkeypatch, tmp_path, index):
    registry = _FakeRegistry("succeeded")
    _with_server(monkeypatch, registry)
    monkeypatch.setattr(attack_tools, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(attack_tools, "_offline", lambda: True)

    with pytest.raises(AttackDataError, match="cannot be downloaded"):
        attack_tools.load_index("enterprise-attack")
    assert registry.submitted == []


def test_an_unreadable_deadline_falls_back_to_fetching_inline(monkeypatch, tmp_path, index):
    """A misconfigured BINARY_MCP_INLINE_DEADLINE must not block the dataset."""
    registry = _FakeRegistry("succeeded")

    def boom():
        raise ValueError("BINARY_MCP_INLINE_DEADLINE must be 0-900")

    monkeypatch.setattr(attack_tools, "_job_degrade", (registry, boom))
    _cold_cache(monkeypatch, tmp_path, index)

    loaded = attack_tools.load_index("enterprise-attack")

    assert registry.submitted == []
    assert loaded["entities"] == index["entities"]


def test_the_real_registry_can_actually_run_the_fetch(monkeypatch, tmp_path, index):
    """End to end against JobRegistry itself, not a fake.

    The fake above is shaped to the registry's contract, but a fake is only
    ever as good as the reading that produced it -- and the first version of
    this one called ``fn()`` where the registry calls ``fn(context)``, so the
    whole degrade path raised TypeError inside the job while every test here
    reported green. This one submits through the real registry, so that class
    of mistake fails here rather than on a user's first cold start.
    """
    from src.engines.jobs import JobRegistry

    registry = JobRegistry(tmp_path / "jobs")
    try:
        monkeypatch.setattr(attack_tools, "_job_degrade", (registry, lambda: 30.0))
        _cold_cache(monkeypatch, tmp_path, index)

        loaded = attack_tools.load_index("enterprise-attack")

        assert loaded["entities"] == index["entities"]
        assert (tmp_path / "enterprise-attack-index.json").exists()
    finally:
        registry.shutdown()
