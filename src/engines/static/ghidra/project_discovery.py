"""
Discovery of on-disk Ghidra projects, without starting a JVM.

Exists so ``analyze_binary`` can attach to a project a human built and
annotated in the Ghidra GUI -- picking up their renames and comments -- rather
than always importing the binary into a fresh throwaway project. Listing has to
be cheap (an MCP client calls it interactively, and spinning up
``analyzeHeadless`` just to read a directory would cost 20+ seconds), so
everything here is pure filesystem inspection.

A project on disk is a ``<name>.gpr`` file beside a ``<name>.rep`` directory.
Program names live in ``<name>.rep/idata/~index.dat``; that file's format is
stable and simple, but it is still Ghidra's private business, so every parse
here degrades to "programs unknown" rather than raising. Callers must treat
``GhidraProject.programs is None`` as "could not enumerate" and stay useful --
``analyzeHeadless -process`` with no argument processes every program in the
project folder, so not knowing the names never blocks an attach.

Two storage schemes exist. Current Ghidra writes the *indexed* filesystem
(``~index.dat``); older projects use the *mangled* scheme, where each item has
a ``<storage>.prp`` XML property file. We read the index first and fall back to
scanning ``.prp`` files, so both answer.
"""

import logging
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from src.utils.config import get_ghidra_project_dirs, get_managed_project_dir

logger = logging.getLogger(__name__)

# ~index.dat line grammar, from IndexedLocalFileSystem / IndexedV1LocalFileSystem.
# Folder lines start with "/", item lines carry a two-space indent, and the
# trailing NEXT-ID / MD5 / VERSION lines are bookkeeping we skip.
_INDEX_FILE = "~index.dat"
_INDEX_ITEM_INDENT = "  "
_INDEX_ITEM_SEPARATOR = ":"
_INDEX_SKIP_PREFIXES = ("VERSION=", "NEXT-ID:", "MD5:")

# Ghidra's content type for an executable it has imported. Data type archives
# and other project items carry different values; we surface the type rather
# than filtering on it so a caller can see everything the project holds.
_PROGRAM_CONTENT_TYPE = "Program"

# Guard on the .rep size walk. A project directory is normally a few hundred
# files, but a long-lived one with many checkpoints can be far larger, and this
# runs on an interactive listing call.
_MAX_SIZE_WALK_FILES = 50_000


@dataclass
class GhidraProgram:
    """One item inside a project (usually an imported executable)."""

    name: str
    folder: str = "/"
    content_type: str | None = None

    @property
    def is_program(self) -> bool:
        """True when Ghidra tagged this item as an executable.

        Unknown content type reads as True: the mangled-scheme fallback and a
        partial index parse both leave it None, and callers use this to decide
        what to *offer*, where a false negative hides a valid target.
        """
        return self.content_type in (None, _PROGRAM_CONTENT_TYPE)

    @property
    def path(self) -> str:
        """Logical project path, e.g. ``/sub/folder/thing.exe``."""
        if self.folder in ("", "/"):
            return f"/{self.name}"
        return f"{self.folder.rstrip('/')}/{self.name}"


@dataclass
class GhidraProject:
    """A ``<name>.gpr`` + ``<name>.rep`` pair on disk."""

    name: str
    directory: Path
    gpr_path: Path
    rep_path: Path
    managed: bool
    locked: bool
    modified: float | None = None
    size_bytes: int = 0
    programs: list[GhidraProgram] | None = None
    program_error: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def program_names(self) -> list[str]:
        """Names of the items that look like executables (empty if unknown)."""
        return [p.name for p in (self.programs or []) if p.is_program]


def _is_locked(directory: Path, name: str) -> bool:
    """True when a lock file suggests the project is open elsewhere.

    Ghidra writes ``<name>.lock`` while a project is held (the GUI, or another
    headless run). ``<name>.lock~`` is the companion it leaves behind. A stale
    lock from a crashed session looks identical from out here -- we report the
    fact and let the caller decide, rather than guessing at liveness.
    """
    return (directory / f"{name}.lock").exists() or \
        (directory / f"{name}.lock~").exists()


def _directory_size(root: Path) -> int:
    """Recursive byte size of a directory, bounded and never raising."""
    total = 0
    seen = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(root, onerror=None):
            for fname in filenames:
                seen += 1
                if seen > _MAX_SIZE_WALK_FILES:
                    return total
                try:
                    total += (Path(dirpath) / fname).stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total


def _parse_index_dat(index_path: Path) -> list[GhidraProgram]:
    """Parse ``~index.dat`` into the items it lists.

    Format (IndexedLocalFileSystem.writeIndex)::

        VERSION=1                       <- absent in version 0
        /                               <- folder line, always starts with "/"
          <storage>:<name>[:<fileId>]   <- item line, two-space indent
        /sub
          <storage>:<name>[:<fileId>]
        NEXT-ID:<hex>
        MD5:<hex>

    The item split mirrors ``IndexedV1LocalFileSystem.parseIndexItem``
    exactly -- first ``:`` ends the storage name, and a later ``:`` at a
    non-zero offset starts the file id. Names containing a colon are
    ambiguous in Ghidra's own parser too, so matching it bug-for-bug is the
    only way to agree with what Ghidra will actually open.
    """
    programs: list[GhidraProgram] = []
    current_folder = "/"

    with open(index_path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line or line.startswith(_INDEX_SKIP_PREFIXES):
                continue
            if line.startswith("/"):
                current_folder = line
                continue
            if not line.startswith(_INDEX_ITEM_INDENT):
                continue
            entry = line[len(_INDEX_ITEM_INDENT):]
            sep = entry.find(_INDEX_ITEM_SEPARATOR)
            if sep < 0:
                continue
            name = entry[sep + 1:]
            tail = name.find(_INDEX_ITEM_SEPARATOR)
            if tail > 0:
                name = name[:tail]
            if name:
                programs.append(GhidraProgram(name=name, folder=current_folder))

    return programs


def _content_type_from_prp(prp_path: Path) -> str | None:
    """Read CONTENT_TYPE out of a Ghidra ``.prp`` property file.

    The file is small XML holding ``<STATE NAME=... TYPE=... VALUE=.../>``
    elements. We accept any element carrying those attributes rather than
    pinning the surrounding element names, and fall back to a regex when the
    XML does not parse -- the value is advisory (it only labels an item as a
    Program vs a data type archive), so a miss costs nothing.
    """
    try:
        text = prp_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    try:
        root = ET.fromstring(text)  # nosec B314 - local Ghidra metadata, no DTDs
        for elem in root.iter():
            if elem.get("NAME") == "CONTENT_TYPE":
                value = elem.get("VALUE")
                if value:
                    return value
    except ET.ParseError:
        pass

    match = re.search(
        r'NAME="CONTENT_TYPE"[^>]*?VALUE="([^"]*)"', text
    )
    return match.group(1) if match else None


def _name_from_prp(prp_path: Path) -> str | None:
    """Read the item's logical NAME out of a ``.prp`` property file."""
    try:
        text = prp_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    try:
        root = ET.fromstring(text)  # nosec B314 - local Ghidra metadata, no DTDs
        for elem in root.iter():
            if elem.get("NAME") == "NAME":
                value = elem.get("VALUE")
                if value:
                    return value
    except ET.ParseError:
        pass

    match = re.search(r'NAME="NAME"[^>]*?VALUE="([^"]*)"', text)
    return match.group(1) if match else None


def _scan_prp_files(idata: Path) -> list[GhidraProgram]:
    """Enumerate items by walking ``.prp`` property files (mangled scheme).

    The on-disk directory names are mangled, so the logical folder path can't
    be reconstructed from them; folder is left as ``/`` and callers that need
    a subfolder must say so explicitly.
    """
    programs: list[GhidraProgram] = []
    for prp in sorted(idata.rglob("*.prp")):
        name = _name_from_prp(prp)
        if not name:
            continue
        programs.append(
            GhidraProgram(
                name=name,
                folder="/",
                content_type=_content_type_from_prp(prp),
            )
        )
    return programs


def _enrich_content_types(idata: Path, programs: list[GhidraProgram]) -> None:
    """Best-effort: label index-derived items with their content type.

    The index carries names but not types; the types live in the ``.prp``
    side files. We match on the logical name rather than trying to map a
    storage name onto a path, because the indexed scheme's storage layout is
    deliberately not a mirror of the logical tree.
    """
    by_name: dict[str, list[GhidraProgram]] = {}
    for prog in programs:
        by_name.setdefault(prog.name, []).append(prog)

    try:
        prp_files = list(idata.rglob("*.prp"))
    except OSError:
        return

    for prp in prp_files:
        name = _name_from_prp(prp)
        if not name or name not in by_name:
            continue
        content_type = _content_type_from_prp(prp)
        if not content_type:
            continue
        for prog in by_name[name]:
            if prog.content_type is None:
                prog.content_type = content_type


def read_project_programs(
    rep_path: Path,
) -> tuple[list[GhidraProgram] | None, str | None]:
    """Enumerate the items inside a ``.rep`` directory.

    Returns ``(programs, error)``. ``programs is None`` means enumeration
    failed and the caller should treat the program list as unknown -- which is
    survivable, since ``-process`` without a name takes every program in the
    folder.
    """
    idata = rep_path / "idata"
    if not idata.is_dir():
        return None, f"no idata directory under {rep_path.name}"

    index_path = idata / _INDEX_FILE
    if index_path.is_file():
        try:
            programs = _parse_index_dat(index_path)
        except OSError as e:
            return None, f"could not read {_INDEX_FILE}: {e}"
        except Exception as e:  # malformed index must not break listing
            logger.debug("Failed parsing %s: %s", index_path, e)
            programs = []
        if programs:
            try:
                _enrich_content_types(idata, programs)
            except Exception as e:
                logger.debug("Content-type enrichment failed for %s: %s", idata, e)
            return programs, None

    # Legacy mangled scheme, or an index we could not make sense of.
    try:
        programs = _scan_prp_files(idata)
    except Exception as e:
        return None, f"could not scan property files: {e}"

    if programs:
        return programs, None
    return None, "no project items found in index or property files"


def discover_projects(
    directories: list[Path] | None = None,
    *,
    include_programs: bool = True,
    include_sizes: bool = True,
) -> list[GhidraProject]:
    """Find every Ghidra project under the configured directories.

    Args:
        directories: Where to look. Defaults to ``get_ghidra_project_dirs()``
            -- the managed directory plus anything in ``$GHIDRA_PROJECT_DIR``.
        include_programs: Enumerate the programs inside each project. Costs a
            small read per project; turn it off for a bare inventory.
        include_sizes: Walk each ``.rep`` for its on-disk size.

    Returns:
        Projects sorted newest-modified first. A project reachable through two
        configured directories is reported once.
    """
    if directories is None:
        directories = get_ghidra_project_dirs()

    managed_dir = get_managed_project_dir()
    try:
        managed_key = str(managed_dir.resolve())
    except OSError:
        managed_key = str(managed_dir)

    projects: list[GhidraProject] = []
    seen: set[str] = set()

    for directory in directories:
        if not directory.is_dir():
            continue
        try:
            gpr_files = sorted(directory.glob("*.gpr"))
        except OSError as e:
            logger.warning("Could not list Ghidra projects in %s: %s", directory, e)
            continue

        for gpr in gpr_files:
            name = gpr.stem
            rep = directory / f"{name}.rep"
            try:
                key = str(gpr.resolve())
            except OSError:
                key = str(gpr)
            if key in seen:
                continue
            seen.add(key)

            try:
                directory_key = str(directory.resolve())
            except OSError:
                directory_key = str(directory)

            try:
                modified = gpr.stat().st_mtime
            except OSError:
                modified = None

            project = GhidraProject(
                name=name,
                directory=directory,
                gpr_path=gpr,
                rep_path=rep,
                managed=directory_key == managed_key,
                locked=_is_locked(directory, name),
                modified=modified,
                size_bytes=(
                    _directory_size(rep) if include_sizes and rep.is_dir() else 0
                ),
            )

            if include_programs and rep.is_dir():
                project.programs, project.program_error = read_project_programs(rep)
            elif include_programs:
                project.program_error = f"missing {name}.rep directory"

            projects.append(project)

    projects.sort(key=lambda p: (p.modified or 0.0), reverse=True)
    return projects


def find_project(
    name: str, directories: list[Path] | None = None
) -> GhidraProject | None:
    """Locate one project by name, or None.

    Accepts a bare project name or a path to its ``.gpr``, so a caller can
    paste whatever ``list_ghidra_projects`` showed them. A path outside the
    configured directories still resolves -- discovery is a convenience, not
    a boundary, and the user naming an explicit path has already decided.
    """
    if not name:
        return None

    candidate = Path(name).expanduser()
    if candidate.suffix == ".gpr" and candidate.is_file():
        directories = [candidate.parent]
        name = candidate.stem

    for project in discover_projects(directories):
        if project.name == name:
            return project
    return None
