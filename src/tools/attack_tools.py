"""
MITRE ATT&CK -- techniques, threat-actor groups, and the software they use.

This is the one integration here with no API key and no rate limit: ATT&CK is
published as STIX 2.1 bundles in a public repository
(https://github.com/mitre-attack/attack-stix-data). That makes it the cheapest
context in the server to operate and the only one that works fully offline once
fetched.

It is also the spine the other integrations hang off. MalwareBazaar and
ThreatFox give you a family name; ATT&CK turns that name into the techniques
the family uses and the groups that deploy it. VirusTotal's sandbox report
gives you observed behaviour; ATT&CK gives that behaviour an identifier a
report can cite.

Why the data is distilled rather than queried in place
-----------------------------------------------------
The Enterprise bundle is ~51MB and ~26,000 objects, of which ~21,000 are STIX
relationship objects. Re-reading that per tool call would be slow, and keeping
it on disk for three domains would cost ~150MB for data that is mostly
cross-references this server never needs.

So the bundle is fetched once, reduced to the entities and relationships these
tools actually answer with, and written to a compact index; the bundle itself
is discarded. Measured on Enterprise v19.2: 51MB and 26,086 objects in, 2.7MB
and 1,933 entities out, reloading in ~0.02s instead of ~0.5s. A refresh
re-downloads; there is no incremental update, because at this size there is no
need for one.

Tactic names are read from the bundle's own ``x-mitre-tactic`` objects rather
than hardcoded. ATT&CK renames tactics between versions -- v19 reports T1055
under "stealth" where earlier versions said "defense-evasion" -- and a
hardcoded table would silently mislabel techniques after an upgrade.

Trust note: unlike every other integration in this server, ATT&CK content is
NOT attacker-authored. It is a curated knowledge base written by MITRE, in the
same category as the sandbox-vendor verdicts vt_behavior leaves outside its
untrusted envelope. It is therefore not fenced -- see the entry for this module
in tests/test_untrusted_rollout.py.
"""

import json
import logging
import re
from pathlib import Path

from src.integrations import IntegrationClient, IntegrationError, ProviderConfig

logger = logging.getLogger(__name__)


class AttackDataError(IntegrationError):
    """
    An ATT&CK dataset failure whose message this module wrote itself.

    Audit F-10: raise sites are the curated sentences below plus the shared
    client's status-line and network messages. The one path that could quote a
    filesystem path -- a failed cache write -- is routed through
    ``safe_path_error`` in the handler instead.
    """


ATTACK_INDEX_URL_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"

ATTACK_DIR_ENV = "ATTACK_DATA_DIR"
ATTACK_DOMAIN_ENV = "ATTACK_DOMAIN"
ATTACK_OFFLINE_ENV = "ATTACK_OFFLINE"
ATTACK_MAX_BUNDLE_MB_ENV = "ATTACK_MAX_BUNDLE_MB"
ATTACK_TIMEOUT_ENV = "ATTACK_TIMEOUT"

#: The three published matrices. Enterprise is the default because this server
#: analyses PE, ELF and Mach-O binaries.
ATTACK_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
DEFAULT_DOMAIN = "enterprise-attack"

#: Enterprise is ~51MB today and grows every release, so the ceiling is well
#: clear of it rather than snug against it.
DEFAULT_MAX_BUNDLE_MB = 128

#: STIX types this server answers questions about. Everything else in the
#: bundle -- data components, analytics, detection strategies, matrices -- is
#: dropped during distillation.
_ENTITY_TYPES = ("attack-pattern", "intrusion-set", "malware", "tool", "campaign")

#: Human labels for those STIX types.
_KIND_LABELS = {
    "attack-pattern": "Technique",
    "intrusion-set": "Group",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
}

#: ATT&CK external IDs: T1055/T1055.001 techniques, G#### groups, S#### software,
#: C#### campaigns, M#### mitigations. Validated before use so a lookup argument
#: cannot become a cache filename or a URL path segment.
_ATTACK_ID_RE = re.compile(r"\A(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|C\d{4}|M\d{4})\Z")

#: Cap on a rendered description. Some ATT&CK technique descriptions run to
#: several thousand characters of prose.
_DESCRIPTION_CHARS = 1200

#: Rows per related-entity section.
_ROW_LIMIT = 20


def _config_str(key: str, default: str) -> str:
    from src.utils.config import get_config
    return (get_config(key) or default).strip()


def domain() -> str:
    """The configured ATT&CK matrix, defaulting to Enterprise."""
    configured = _config_str(ATTACK_DOMAIN_ENV, DEFAULT_DOMAIN).lower()
    return configured if configured in ATTACK_DOMAINS else DEFAULT_DOMAIN


def data_dir() -> Path:
    """Where the distilled index lives."""
    from src.utils.config import get_cache_dir, get_config

    configured = get_config(ATTACK_DIR_ENV)
    return Path(configured) if configured else get_cache_dir() / "attack"


def index_path(matrix: str | None = None) -> Path:
    return data_dir() / f"{matrix or domain()}-index.json"


def _offline() -> bool:
    from src.utils.config import get_config_bool
    return get_config_bool(ATTACK_OFFLINE_ENV, False)


def _max_bundle_bytes() -> int:
    from src.utils.config import get_config_int
    megabytes = get_config_int(ATTACK_MAX_BUNDLE_MB_ENV, DEFAULT_MAX_BUNDLE_MB)
    return max(8, min(megabytes, 1024)) * 1024 * 1024


client = IntegrationClient(
    ProviderConfig(
        name="MITRE ATT&CK",
        base_url=ATTACK_INDEX_URL_BASE,
        # No credential: ATT&CK is served as static files from a public repo.
        auth_header="",
        key_config_keys=(),
        timeout_config_key=ATTACK_TIMEOUT_ENV,
        default_timeout=120,
        max_timeout=600,
        max_response_bytes=DEFAULT_MAX_BUNDLE_MB * 1024 * 1024,
    ),
    AttackDataError,
)


# ---------------------------------------------------------------------------
# Fetch and distil
# ---------------------------------------------------------------------------


def _external_id(obj: dict) -> tuple[str | None, str | None]:
    """The object's ATT&CK ID and web URL, from its mitre-attack reference."""
    for reference in obj.get("external_references") or []:
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id"), reference.get("url")
    return None, None


def distil(bundle: dict, version: str) -> dict:
    """
    Reduce a STIX bundle to the entities and links these tools answer with.

    Args:
        bundle: The parsed STIX bundle.
        version: ATT&CK release the bundle came from, recorded so
            ``attack_status`` can report what is cached.

    Returns:
        The index written to disk: tactic labels, entities by ATT&CK ID, and
        relationships as ``[type, source_id, target_id]`` triples. STIX UUIDs
        are resolved to ATT&CK IDs here so nothing downstream has to carry a
        second identifier space.
    """
    objects = bundle.get("objects") or []

    tactics = {
        obj["x_mitre_shortname"]: obj["name"]
        for obj in objects
        if obj.get("type") == "x-mitre-tactic" and obj.get("x_mitre_shortname")
    }

    entities: dict[str, dict] = {}
    by_stix: dict[str, str] = {}

    for obj in objects:
        if obj.get("type") not in _ENTITY_TYPES:
            continue
        attack_id, url = _external_id(obj)
        if not attack_id:
            continue
        by_stix[obj["id"]] = attack_id
        entities[attack_id] = {
            "id": attack_id,
            "name": obj.get("name", ""),
            "kind": obj["type"],
            "url": url or "",
            "description": obj.get("description", ""),
            "aliases": obj.get("aliases") or obj.get("x_mitre_aliases") or [],
            "platforms": obj.get("x_mitre_platforms") or [],
            "tactics": [
                tactics.get(phase["phase_name"], phase["phase_name"])
                for phase in obj.get("kill_chain_phases") or []
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
            "subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            # Deprecated and revoked objects are KEPT, flagged rather than
            # dropped: an old report citing T1064 should still resolve, with a
            # note that ATT&CK has retired it, instead of coming back "unknown".
            "retired": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
        }

    relationships = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        source = by_stix.get(obj.get("source_ref"))
        target = by_stix.get(obj.get("target_ref"))
        if source and target:
            relationships.append([obj.get("relationship_type"), source, target])

    return {
        "attack_version": version,
        "tactics": tactics,
        "entities": entities,
        "relationships": relationships,
    }


def fetch_index(matrix: str | None = None) -> dict:
    """
    Download the current bundle for one matrix and distil it.

    Raises:
        AttackDataError: If the collection index has no entry for the matrix,
            or the download fails.
    """
    matrix = matrix or domain()

    catalogue = client.request("index.json", max_bytes=8 * 1024 * 1024).payload
    version = ""
    bundle_url = ""
    for collection in catalogue.get("collections") or []:
        versions = collection.get("versions") or []
        if not versions:
            continue
        url = str(versions[0].get("url", ""))
        if f"/{matrix}/" in url:
            version = str(versions[0].get("version", ""))
            bundle_url = url
            break

    if not bundle_url:
        raise AttackDataError(
            f"The ATT&CK collection index lists no bundle for {matrix}"
        )

    # The index gives absolute URLs on the same host the client is rooted at.
    if not bundle_url.startswith(ATTACK_INDEX_URL_BASE):
        raise AttackDataError(
            "The ATT&CK collection index pointed somewhere unexpected; refusing "
            "to fetch it"
        )
    path = bundle_url[len(ATTACK_INDEX_URL_BASE):]

    bundle = client.request(path, max_bytes=_max_bundle_bytes()).payload
    if not bundle.get("objects"):
        raise AttackDataError(f"The {matrix} bundle contained no objects")

    return distil(bundle, version)


def load_index(matrix: str | None = None, refresh: bool = False) -> dict:
    """
    Return the distilled index, fetching it if it is missing or stale.

    Args:
        matrix: ATT&CK matrix; defaults to the configured one.
        refresh: Re-download even when a cached index exists.

    Raises:
        AttackDataError: When no index is cached and one cannot be fetched --
            including when ``ATTACK_OFFLINE`` forbids the attempt.
    """
    matrix = matrix or domain()
    cached = index_path(matrix)

    if not refresh and cached.exists():
        try:
            return json.loads(cached.read_text(encoding="utf-8"))
        except (ValueError, OSError) as e:
            logger.warning(f"ATT&CK index at {cached} unreadable, refetching: {e}")

    if _offline():
        raise AttackDataError(
            f"No cached ATT&CK data for {matrix} and {ATTACK_OFFLINE_ENV} is set, "
            "so it cannot be downloaded. Unset it once to populate the cache."
        )

    index = fetch_index(matrix)
    cached.parent.mkdir(parents=True, exist_ok=True)
    cached.write_text(json.dumps(index), encoding="utf-8")
    return index


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def normalise_attack_id(value: str) -> str:
    """
    Validate an ATT&CK external ID.

    Raises:
        ValueError: If it is not a well-formed ID. Validated rather than merely
            upper-cased because the value reaches a cache filename and a URL
            path in other code paths; the same reasoning as hash validation in
            src/integrations/hashes.py.
    """
    candidate = (value or "").strip().upper()
    if not _ATTACK_ID_RE.match(candidate):
        raise ValueError(
            f"Invalid ATT&CK ID: {value!r}. Expected a form like T1055, "
            "T1055.001, G0016, S0154 or C0001."
        )
    return candidate


def resolve(index: dict, value: str, kinds: tuple[str, ...] = ()) -> dict | None:
    """
    Find one entity by ATT&CK ID, exact name, or exact alias.

    Names and aliases are matched case-insensitively, because an analyst types
    "cobalt strike" and ATT&CK stores "Cobalt Strike".
    """
    entities = index.get("entities") or {}
    wanted = (value or "").strip()
    if not wanted:
        return None

    direct = entities.get(wanted.upper())
    if direct and (not kinds or direct["kind"] in kinds):
        return direct

    folded = wanted.casefold()
    alias_match = None
    for entity in entities.values():
        if kinds and entity["kind"] not in kinds:
            continue
        if entity["name"].casefold() == folded:
            return entity
        if alias_match is None and any(
            str(alias).casefold() == folded for alias in entity.get("aliases") or []
        ):
            alias_match = entity
    return alias_match


def related(index: dict, attack_id: str, relationship: str,
            as_source: bool = True, kinds: tuple[str, ...] = ()) -> list[dict]:
    """Entities linked to ``attack_id`` by one relationship type."""
    entities = index.get("entities") or {}
    found = []
    for rel_type, source, target in index.get("relationships") or []:
        if rel_type != relationship:
            continue
        this, other = (source, target) if as_source else (target, source)
        if this != attack_id:
            continue
        entity = entities.get(other)
        if entity and (not kinds or entity["kind"] in kinds):
            found.append(entity)
    return sorted(found, key=lambda e: e["id"])


def _summary(entity: dict) -> str:
    """One line identifying an entity in a list."""
    label = _KIND_LABELS.get(entity["kind"], entity["kind"])
    retired = " [retired]" if entity.get("retired") else ""
    return f"  {entity['id']}  {entity['name']} ({label}){retired}"


def _describe(entity: dict) -> list[str]:
    """The shared header block for a single-entity lookup."""
    lines = [
        f"{_KIND_LABELS.get(entity['kind'], entity['kind'])}: "
        f"{entity['id']}  {entity['name']}"
    ]
    if entity.get("retired"):
        lines.append(
            "  NOTE: ATT&CK has deprecated or revoked this entry. It still "
            "resolves so older reports citing it can be read."
        )
    if entity.get("tactics"):
        lines.append(f"  Tactics: {', '.join(entity['tactics'])}")
    if entity.get("platforms"):
        lines.append(f"  Platforms: {', '.join(entity['platforms'])}")
    if entity.get("aliases"):
        others = [a for a in entity["aliases"] if a != entity["name"]]
        if others:
            lines.append(f"  Also known as: {', '.join(others)}")
    if entity.get("url"):
        lines.append(f"  Reference: {entity['url']}")

    description = (entity.get("description") or "").strip()
    if description:
        if len(description) > _DESCRIPTION_CHARS:
            description = (
                description[:_DESCRIPTION_CHARS]
                + f"\n  ... [truncated, {len(description)} characters total; "
                "see the reference URL for the full text]"
            )
        lines.append("")
        lines.append(description)
    return lines


def _section(title: str, entities: list[dict]) -> list[str]:
    if not entities:
        return []
    lines = ["", f"{title} ({len(entities)}):"]
    lines.extend(_summary(e) for e in entities[:_ROW_LIMIT])
    if len(entities) > _ROW_LIMIT:
        lines.append(f"  ... and {len(entities) - _ROW_LIMIT} more")
    return lines


def register_attack_tools(app, session_manager=None):
    """
    Register the MITRE ATT&CK tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
    """
    from src.tools.error_hygiene import safe_path_error
    from src.utils.security import safe_error_message

    @app.tool()
    def attack_status(refresh: bool = False) -> str:
        """
        Show the cached MITRE ATT&CK dataset, and optionally refresh it.

        ATT&CK needs no API key. The data is fetched once from MITRE's public
        STIX repository, reduced to a compact index, and then served entirely
        from disk -- so every other attack_* tool works offline after this.

        Args:
            refresh: Re-download the bundle and rebuild the index.

        Returns:
            Dataset version, entity counts and cache location.

        Example:
            attack_status()
            attack_status(refresh=True)
        """
        try:
            matrix = domain()
            cached = index_path(matrix)
            existed = cached.exists()

            index = load_index(matrix, refresh=refresh)

            kinds: dict[str, int] = {}
            for entity in (index.get("entities") or {}).values():
                label = _KIND_LABELS.get(entity["kind"], entity["kind"])
                kinds[label] = kinds.get(label, 0) + 1

            output = [
                "MITRE ATT&CK DATASET",
                f"Matrix: {matrix}",
                f"ATT&CK version: {index.get('attack_version') or 'unknown'}",
                "",
            ]
            if refresh:
                output.append("Refreshed from MITRE's STIX repository.")
            elif existed:
                output.append("Served from the local cache (no network access).")
            else:
                output.append("Downloaded and cached; later calls are offline.")

            output.append("")
            output.append("Contents:")
            for label, count in sorted(kinds.items()):
                output.append(f"  {label}: {count}")
            output.append(
                f"  Relationships: {len(index.get('relationships') or [])}"
            )
            output.append("")
            output.append(f"Cache: {cached}")
            output.append(
                f"Set {ATTACK_DOMAIN_ENV} to one of: {', '.join(ATTACK_DOMAINS)}"
            )
            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AttackDataError as e:
            return f"ATT&CK error: {e}"
        except OSError as e:
            return safe_path_error("attack_status", e, "ATT&CK cache directory")
        except Exception as e:
            logger.error(f"attack_status failed: {e}")
            return safe_error_message("Failed to read ATT&CK dataset", e)

    @app.tool()
    def attack_lookup_technique(technique: str) -> str:
        """
        Look up an ATT&CK technique by ID or name.

        Returns the technique's tactics, platforms and description, its
        sub-techniques, and -- the useful part for attribution -- which groups
        and which malware families are recorded as using it.

        Args:
            technique: ATT&CK ID (T1055, T1055.001) or exact name
                ("Process Injection")

        Returns:
            Technique detail with the groups and software that use it.

        Example:
            attack_lookup_technique("T1055")
            attack_lookup_technique("Process Injection")
        """
        try:
            index = load_index()
            entity = resolve(index, technique, kinds=("attack-pattern",))
            if not entity:
                return (
                    f"No ATT&CK technique matched {technique!r}. "
                    "Try an ID like T1055, or attack_search to find one by keyword."
                )

            output = _describe(entity)

            parents = related(index, entity["id"], "subtechnique-of")
            if parents:
                output.append("")
                output.append(f"Sub-technique of: {parents[0]['id']} {parents[0]['name']}")

            output.extend(_section(
                "Sub-techniques",
                related(index, entity["id"], "subtechnique-of", as_source=False),
            ))
            output.extend(_section(
                "Used by groups",
                related(index, entity["id"], "uses", as_source=False,
                        kinds=("intrusion-set",)),
            ))
            output.extend(_section(
                "Used by software",
                related(index, entity["id"], "uses", as_source=False,
                        kinds=("malware", "tool")),
            ))
            output.extend(_section(
                "Seen in campaigns",
                related(index, entity["id"], "uses", as_source=False,
                        kinds=("campaign",)),
            ))
            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AttackDataError as e:
            return f"ATT&CK error: {e}"
        except Exception as e:
            logger.error(f"attack_lookup_technique failed: {e}")
            return safe_error_message("Failed to look up technique", e)

    @app.tool()
    def attack_lookup_group(group: str) -> str:
        """
        Look up an ATT&CK threat-actor group by ID, name or alias.

        Alias matching is what makes this useful in practice: vendors name the
        same actor differently, and ATT&CK records the aliases, so "Bluenoroff"
        and "APT38" both resolve to G0082.

        Args:
            group: ATT&CK ID (G0016), name ("APT29"), or a vendor alias
                ("Cozy Bear", "Bluenoroff")

        Returns:
            The group's aliases and description, the techniques it uses, and
            the software it is recorded as using.

        Example:
            attack_lookup_group("APT29")
            attack_lookup_group("Bluenoroff")
        """
        try:
            index = load_index()
            entity = resolve(index, group, kinds=("intrusion-set",))
            if not entity:
                return (
                    f"No ATT&CK group matched {group!r}. ATT&CK tracks a subset "
                    "of named actors; try attack_search for a keyword match."
                )

            output = _describe(entity)
            output.extend(_section(
                "Software used",
                related(index, entity["id"], "uses", kinds=("malware", "tool")),
            ))
            output.extend(_section(
                "Techniques used",
                related(index, entity["id"], "uses", kinds=("attack-pattern",)),
            ))
            output.extend(_section(
                "Attributed campaigns",
                related(index, entity["id"], "attributed-to", as_source=False),
            ))
            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AttackDataError as e:
            return f"ATT&CK error: {e}"
        except Exception as e:
            logger.error(f"attack_lookup_group failed: {e}")
            return safe_error_message("Failed to look up group", e)

    @app.tool()
    def attack_lookup_software(software: str) -> str:
        """
        Look up ATT&CK malware or tooling by ID, name or alias.

        The natural follow-up to a family name from mb_lookup, threatfox_lookup_ioc
        or a VirusTotal detection: ATT&CK turns the name into the techniques the
        family implements and the groups that deploy it.

        Args:
            software: ATT&CK ID (S0154), name ("Cobalt Strike"), or an alias

        Returns:
            The entry's aliases and description, the techniques it implements,
            and the groups recorded as using it.

        Example:
            attack_lookup_software("Cobalt Strike")
            attack_lookup_software("S0154")
        """
        try:
            index = load_index()
            entity = resolve(index, software, kinds=("malware", "tool"))
            if not entity:
                return (
                    f"No ATT&CK software matched {software!r}. ATT&CK covers "
                    "named families rather than every sample; try attack_search."
                )

            output = _describe(entity)
            output.extend(_section(
                "Techniques implemented",
                related(index, entity["id"], "uses", kinds=("attack-pattern",)),
            ))
            output.extend(_section(
                "Used by groups",
                related(index, entity["id"], "uses", as_source=False,
                        kinds=("intrusion-set",)),
            ))
            output.extend(_section(
                "Seen in campaigns",
                related(index, entity["id"], "uses", as_source=False,
                        kinds=("campaign",)),
            ))
            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AttackDataError as e:
            return f"ATT&CK error: {e}"
        except Exception as e:
            logger.error(f"attack_lookup_software failed: {e}")
            return safe_error_message("Failed to look up software", e)

    @app.tool()
    def attack_search(query: str, kind: str = "all", limit: int = 25) -> str:
        """
        Search ATT&CK by keyword across techniques, groups, software and campaigns.

        Matches names and aliases first, then descriptions, so a specific term
        ranks above a passing mention of it.

        Args:
            query: Keyword, e.g. "credential dumping", "lsass", "keylog"
            kind: Restrict to "technique", "group", "software", "campaign",
                or "all" (default)
            limit: Maximum results (1-200, default 25)

        Returns:
            Matching entries, name and alias hits first.

        Example:
            attack_search("lsass")
            attack_search("ransomware", kind="software")
        """
        try:
            needle = (query or "").strip()
            if not needle:
                return "Error: Provide a search term"
            try:
                limit = max(1, min(int(limit), 200))
            except (TypeError, ValueError):
                return f"Error: limit must be an integer, got {limit!r}"

            wanted = {
                "all": (),
                "technique": ("attack-pattern",),
                "group": ("intrusion-set",),
                "software": ("malware", "tool"),
                "campaign": ("campaign",),
            }.get(kind.strip().lower())
            if wanted is None:
                return (
                    f"Error: kind must be one of all, technique, group, "
                    f"software, campaign (got {kind!r})"
                )

            index = load_index()
            folded = needle.casefold()

            named: list[dict] = []
            described: list[dict] = []
            for entity in (index.get("entities") or {}).values():
                if wanted and entity["kind"] not in wanted:
                    continue
                haystack = [entity["name"], *(entity.get("aliases") or [])]
                if any(folded in str(text).casefold() for text in haystack):
                    named.append(entity)
                elif folded in (entity.get("description") or "").casefold():
                    described.append(entity)

            named.sort(key=lambda e: e["id"])
            described.sort(key=lambda e: e["id"])
            ordered = named + described

            output = [
                "MITRE ATT&CK SEARCH",
                f"Query: {needle}",
                f"Scope: {kind}",
                "",
            ]
            if not ordered:
                output.append("No matches.")
                return "\n".join(output)

            output.append(
                f"Found {len(ordered)} match(es); {len(named)} by name or alias."
            )
            output.append("")
            for entity in ordered[:limit]:
                output.append(_summary(entity))
            if len(ordered) > limit:
                output.append(f"  ... and {len(ordered) - limit} more")
            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AttackDataError as e:
            return f"ATT&CK error: {e}"
        except Exception as e:
            logger.error(f"attack_search failed: {e}")
            return safe_error_message("Failed to search ATT&CK", e)

    logger.info("Registered 5 MITRE ATT&CK tools")
