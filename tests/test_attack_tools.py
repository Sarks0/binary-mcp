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
    distil,
    normalise_attack_id,
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


# ---------------------------------------------------------------------------
# Distillation
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# ID validation and resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [("t1055", "T1055"), (" T1055.001 ", "T1055.001"), ("g0016", "G0016"),
     ("S0154", "S0154"), ("c0001", "C0001"), ("m1040", "M1040")],
)
def test_normalise_attack_id_accepts_the_real_forms(raw, expected):
    assert normalise_attack_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "T105", "T10555", "X1055", "T1055.0001", "../../etc/passwd",
     "T1055/../x", "T1055 OR 1=1"],
)
def test_normalise_attack_id_rejects_everything_else(raw):
    """The value reaches a cache filename and a URL path elsewhere."""
    with pytest.raises(ValueError):
        normalise_attack_id(raw)


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


# ---------------------------------------------------------------------------
# Relationship traversal
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Caching: no key, and no network after the first fetch
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tool behaviour
# ---------------------------------------------------------------------------


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
