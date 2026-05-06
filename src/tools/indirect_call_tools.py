"""
Indirect-call & vtable enumeration tools (Wave 2).

Closes the biggest hole in the static call graph: indirect calls
(``CALL [rax+N]``, vtable dispatch, COM/.NET) which never appear in
the direct call edges Ghidra emits.

The Ghidra-side capture lives in ``core_analysis.py`` (per-function
``indirect_calls`` list + reverse index ``xrefs_to_function_indirect``).
This module complements that with a pe-data scanner: walking
``.rdata`` / ``.data`` byte-by-byte in pointer-sized strides looking
for runs of consecutive pointers that all land at known function
entries from the analysis cache. Tags 28-slot driver dispatch tables,
RVA32-stride win32k shadow-table candidates, and (when present) the
GuardCF function table from the PE load-config directory.

Result is persisted into ``context["vtables"]`` so subsequent calls
short-circuit and ``get_xrefs(direction="to", ...)`` can surface a
slot-level "Indirect call candidates" section without re-walking
sections.
"""

from __future__ import annotations

import logging
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

# Recognised section names where vtables / fnptr tables typically live.
_VTABLE_SECTIONS = (".rdata", ".data", ".rodata")

# 28 IRP_MJ_* major-function slots in DRIVER_OBJECT.MajorFunction.
_DRIVER_DISPATCH_SLOTS = 28


def _normalize_addr(value: object) -> str:
    """Match the canonical form server.py::_normalize_xref_addr emits."""
    if value is None:
        return ""
    s = str(value).lower().replace("0x", "").lstrip("0")
    return s or "0"


def _addr_to_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).lower().replace("0x", ""), 16)
    except (ValueError, TypeError):
        return None


def _build_known_function_set(context: dict) -> tuple[dict[int, dict], int | None]:
    """Return ``(known_va_to_func, image_base_int)``.

    ``known_va_to_func`` maps every cached function's entry point
    (parsed as int) to its function dict, so vtable matching is O(1).
    """
    metadata = context.get("metadata") or {}
    image_base = _addr_to_int(metadata.get("image_base"))
    known: dict[int, dict] = {}
    for fn in context.get("functions") or []:
        addr = _addr_to_int(fn.get("address"))
        if addr is not None:
            known[addr] = fn
    return known, image_base


def _detect_pointer_size(pe) -> int:
    """4 for PE32, 8 for PE32+. Defaults to 8 when Magic is unset."""
    try:
        return 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
    except Exception:
        return 8


def _read_section_bytes(section) -> bytes:
    try:
        data = section.get_data()
    except Exception:
        return b""
    return data or b""


def _scan_section_for_runs(
    section,
    pointer_size: int,
    image_base: int | None,
    known_va: dict[int, dict],
    min_run: int,
) -> list[dict]:
    """Walk ``section`` in pointer-sized strides and emit pointer runs
    where every entry lands on a known function entry. Tries absolute
    pointers first, then falls back to RVA-as-pointer reinterpretation
    when no absolute hits land.
    """
    raw = _read_section_bytes(section)
    if len(raw) < pointer_size * min_run:
        return []
    section_va_base = section.VirtualAddress
    if image_base is not None:
        section_va_base = image_base + section.VirtualAddress
    section_name = section.Name.rstrip(b"\x00").decode("utf-8", "replace")

    fmt_abs = "<Q" if pointer_size == 8 else "<I"

    def _walk(values: list[int], stride: int) -> list[dict]:
        runs: list[dict] = []
        current: list[tuple[int, dict]] = []  # (slot_index, func_dict)
        run_start_index: int | None = None
        for slot_idx, va in enumerate(values):
            target = known_va.get(va)
            if target is not None:
                if not current:
                    run_start_index = slot_idx
                current.append((slot_idx - (run_start_index or 0), target))
            else:
                if len(current) >= min_run and run_start_index is not None:
                    runs.append(_emit_run(
                        section_name, section_va_base, stride,
                        run_start_index, current,
                    ))
                current = []
                run_start_index = None
        if len(current) >= min_run and run_start_index is not None:
            runs.append(_emit_run(
                section_name, section_va_base, stride,
                run_start_index, current,
            ))
        return runs

    # Absolute pointers (pointer_size stride).
    abs_values = [
        struct.unpack(fmt_abs, raw[i:i + pointer_size])[0]
        for i in range(0, len(raw) - (pointer_size - 1), pointer_size)
    ]
    abs_runs = _walk(abs_values, pointer_size)
    if abs_runs:
        return abs_runs

    # Fallback: RVA-as-pointer scan (32-bit stride, RVA + image_base).
    if pointer_size == 8 and image_base is not None and len(raw) >= 4 * min_run:
        rva_values = [
            image_base + struct.unpack("<I", raw[i:i + 4])[0]
            for i in range(0, len(raw) - 3, 4)
        ]
        rva_runs = _walk(rva_values, 4)
        # Tag rva-stride runs distinctly so callers can tell.
        for run in rva_runs:
            tags = run.setdefault("tags", [])
            if "WIN32K_SHADOW_TABLE_CANDIDATE" not in tags:
                tags.append("WIN32K_SHADOW_TABLE_CANDIDATE")
        return rva_runs
    return []


def _emit_run(
    section_name: str,
    section_va_base: int,
    stride: int,
    run_start_slot: int,
    entries: list[tuple[int, dict]],
) -> dict:
    table_va = section_va_base + run_start_slot * stride
    targets = []
    for offset_slot, fn in entries:
        targets.append({
            "slot": offset_slot,
            "address": fn.get("address"),
            "name": fn.get("name"),
        })
    record = {
        "section": section_name,
        "address": f"0x{table_va:x}",
        "slot_count": len(entries),
        "stride": stride,
        "targets": targets,
        "tags": [],
    }
    if record["slot_count"] == _DRIVER_DISPATCH_SLOTS:
        record["tags"].append("DRIVER_DISPATCH_TABLE")
    return record


def _walk_guardcf_table(pe, known_va: dict[int, dict], image_base: int) -> dict | None:
    """Read the PE load-config GuardCFFunctionTable when populated and
    return a synthetic vtable record covering every entry that hits a
    known function. Returns ``None`` when the table is absent or
    unreadable.
    """
    try:
        load_cfg = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
        if load_cfg is None:
            return None
        struct_obj = getattr(load_cfg, "struct", None)
        if struct_obj is None:
            return None
        table_va = getattr(struct_obj, "GuardCFFunctionTable", 0) or 0
        count = getattr(struct_obj, "GuardCFFunctionCount", 0) or 0
        if not table_va or not count:
            return None
        # Each entry is a 4-byte RVA followed by an optional metadata
        # byte (size encoded by GUARD_CF_FUNCTION_TABLE_SIZE_MASK in
        # GuardFlags). The metadata byte is implementation-defined; we
        # read the RVA conservatively in 4-byte strides and let any
        # misalignment fall out as misses.
        entries_va = table_va  # already absolute (LoadConfig stores VA)
        targets = []
        for i in range(min(count, 100000)):  # hard sanity ceiling
            entry_offset = i * 4
            try:
                entry_bytes = pe.get_data(
                    entries_va - image_base + entry_offset, 4
                )
            except Exception:
                break
            if not entry_bytes or len(entry_bytes) < 4:
                break
            rva = struct.unpack("<I", entry_bytes)[0]
            target_va = image_base + rva
            fn = known_va.get(target_va)
            if fn is None:
                continue
            targets.append({
                "slot": i,
                "address": fn.get("address"),
                "name": fn.get("name"),
            })
        if not targets:
            return None
        return {
            "section": ".rdata",
            "address": f"0x{table_va:x}",
            "slot_count": len(targets),
            "stride": 4,
            "targets": targets,
            "tags": ["GUARD_CF_FUNCTION_TABLE"],
        }
    except Exception as e:
        logger.debug("GuardCF walk failed: %s", e)
        return None


def _scan(
    binary_path: str,
    context: dict,
    min_run: int,
) -> list[dict]:
    """Run the full pe-data scan and return the list of vtable records."""
    import pefile  # local import to keep the rest of the module importable

    known_va, image_base = _build_known_function_set(context)
    if not known_va:
        return []

    try:
        pe = pefile.PE(str(binary_path), fast_load=True)
    except pefile.PEFormatError:
        return []
    try:
        pe.parse_data_directories()
    except Exception:
        # parse_data_directories may bomb on torn PE files; the section
        # walk below still works against the always-loaded headers.
        pass

    pointer_size = _detect_pointer_size(pe)
    vtables: list[dict] = []

    try:
        for section in pe.sections:
            try:
                section_name = section.Name.rstrip(b"\x00").decode(
                    "utf-8", "replace"
                )
            except Exception:
                continue
            if section_name not in _VTABLE_SECTIONS:
                continue
            vtables.extend(
                _scan_section_for_runs(
                    section, pointer_size, image_base, known_va, min_run,
                )
            )

        if image_base is not None:
            guardcf = _walk_guardcf_table(pe, known_va, image_base)
            if guardcf is not None:
                vtables.append(guardcf)
    finally:
        try:
            pe.close()
        except Exception:
            pass

    return vtables


def _format_vtables(binary_name: str, vtables: list[dict]) -> str:
    if not vtables:
        return (
            f"**Vtable scan for {binary_name}:** *(no fnptr runs found)*\n\n"
            "_No runs of consecutive function pointers in `.rdata`/`.data` "
            "matched known function entries. Possible reasons: stripped "
            "binary with no analyzed functions yet, ASLR-relocated pointers "
            "stored as RVAs only, or a cache that needs `analyze_binary` "
            "to be re-run before scanning._"
        )

    lines = [f"**Vtable scan for {binary_name}:**", ""]
    total_targets = sum(vt.get("slot_count", 0) for vt in vtables)
    lines.append(f"Tables: {len(vtables)} ({total_targets} pointers total)")
    lines.append("")
    for vt in vtables:
        tags = vt.get("tags") or []
        tag_text = f" [{', '.join(tags)}]" if tags else ""
        lines.append(
            f"### `{vt.get('address')}` -- {vt.get('section')}, "
            f"{vt.get('slot_count')} slots, stride {vt.get('stride')} "
            f"bytes{tag_text}"
        )
        for tgt in vt.get("targets") or []:
            name = tgt.get("name") or "?"
            lines.append(
                f"- slot {tgt.get('slot')}: {name} @ {tgt.get('address')}"
            )
        lines.append("")
    return "\n".join(lines)


def register_indirect_call_tools(app, cache, runner=None):
    """Register Wave 2 indirect-call enumeration tools."""
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        sanitize_binary_path,
    )

    @app.tool()
    def find_vtables(binary_path: str, min_run: int = 3) -> str:
        """
        Scan ``.rdata`` / ``.data`` for runs of consecutive function
        pointers (vtables, dispatch tables, fnptr arrays).

        Closes part of the indirect-call gap in the static call graph.
        Each run that contains at least ``min_run`` consecutive pointers
        landing on known function entries (from the cached analysis) is
        emitted with its slot count, stride, and per-slot targets.

        Tagged shapes:

        * ``DRIVER_DISPATCH_TABLE`` -- 28-slot run (matches
          ``DRIVER_OBJECT.MajorFunction`` size on Windows kernel drivers).
        * ``WIN32K_SHADOW_TABLE_CANDIDATE`` -- 4-byte stride RVA fallback
          when the absolute scan finds nothing.
        * ``GUARD_CF_FUNCTION_TABLE`` -- entries derived from the PE
          load-config ``GuardCFFunctionTable`` directory.

        Results are persisted into ``context["vtables"]`` so subsequent
        calls and ``get_xrefs(direction="to", ...)`` can read them
        without re-walking the PE.

        Args:
            binary_path: Path to the analyzed binary
            min_run: Minimum consecutive pointers required to qualify
                as a vtable (default 3)

        Returns:
            Markdown listing grouped by section, or a "(none found)"
            message when no qualifying runs exist.
        """
        try:
            try:
                validated = sanitize_binary_path(binary_path)
            except (PathTraversalError, FileSizeError, FileNotFoundError, ValueError) as e:
                return f"Invalid binary path: {e}"
            binary_path = str(validated)

            try:
                min_run = int(min_run)
            except (TypeError, ValueError):
                return "Error: min_run must be an integer"
            if min_run < 2:
                return "Error: min_run must be >= 2"

            context = cache.get_cached(binary_path)
            if context is None:
                return (
                    "Error: No cached analysis. Run `analyze_binary` first "
                    "so vtable targets can be matched against known "
                    "function entries."
                )

            # Honour an existing cached result when the threshold matches.
            cached_vtables = context.get("vtables")
            cached_min_run = context.get("vtables_min_run")
            if (
                isinstance(cached_vtables, list)
                and cached_min_run == min_run
            ):
                return _format_vtables(Path(binary_path).name, cached_vtables)

            vtables = _scan(binary_path, context, min_run)
            context["vtables"] = vtables
            context["vtables_min_run"] = min_run
            try:
                cache.save_cached(binary_path, context)
            except Exception as e:
                logger.warning("Failed to persist vtables to cache: %s", e)

            return _format_vtables(Path(binary_path).name, vtables)
        except Exception as e:
            logger.exception("find_vtables failed: %s", e)
            return f"Error: {e}"

    logger.info("Registered 1 indirect-call tool")
    return {"find_vtables": find_vtables}
