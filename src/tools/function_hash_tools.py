"""
Function hashing, batch decompilation, and cross-binary comparison tools.

Provides tools for:
- Normalized opcode hashing for cross-binary function identification
- Batch decompilation to reduce MCP round trips
- Function analysis completeness scoring
- Cross-binary function matching via normalized hashes
"""

import hashlib
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Maximum functions per batch decompile request
MAX_BATCH_SIZE = 20

# Safety valve for fuzzy matching to prevent runaway comparisons
MAX_FUZZY_COMPARISONS = 100_000


def _get_capstone_mode(binary_path: str):
    """
    Determine the correct capstone architecture and mode for a binary.

    Uses BinaryCompatibilityChecker to detect architecture, then maps
    to the appropriate capstone constants.

    Args:
        binary_path: Path to the binary file

    Returns:
        Tuple of (capstone.CS_ARCH_*, capstone.CS_MODE_*) or None if unsupported
    """
    import capstone

    from src.utils.compatibility import BinaryCompatibilityChecker

    checker = BinaryCompatibilityChecker()
    info = checker.check_compatibility(binary_path)

    arch = info.architecture.lower()
    bitness = info.bitness

    if "x86" in arch or "x86-64" in arch:
        if bitness == 64:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_64
        else:
            return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    elif "arm64" in arch or "aarch64" in arch:
        return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    elif "arm" in arch:
        return capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
    elif "mips" in arch:
        if bitness == 64:
            return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64
        else:
            return capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32
    elif "powerpc" in arch or "ppc" in arch:
        if bitness == 64:
            return capstone.CS_ARCH_PPC, capstone.CS_MODE_64
        else:
            return capstone.CS_ARCH_PPC, capstone.CS_MODE_32

    return None


# Stack-pointer arithmetic normalisation: collapses prologue/epilogue frame-size
# variance (e.g. ``sub rsp, 0x28`` vs ``sub rsp, 0x38``) so otherwise-identical
# inlined clones hash to the same value.
_STACK_REG_PATTERN = re.compile(r"^(rsp|esp|sp)\b", re.IGNORECASE)
_STACK_IMM_PATTERN = re.compile(r"#?-?0x[0-9a-fA-F]+|#-?\d+")


def _normalize_stack_imm(mnemonic: str, op_str: str) -> tuple[str, int]:
    """
    Replace stack-pointer arithmetic immediates with a STACK_IMM placeholder.

    Targets only ``sub``/``add``/``lea`` instructions whose first operand is a
    stack-pointer register (``rsp``/``esp``/``sp``). Non-stack arithmetic is
    left untouched so unrelated small immediates keep their distinguishing
    power.

    Args:
        mnemonic: Capstone instruction mnemonic
        op_str: Capstone instruction operand string

    Returns:
        Tuple of (normalized_op_str, replacement_count)
    """
    mnem = mnemonic.lower()
    if mnem not in ("sub", "add", "lea"):
        return op_str, 0
    if not _STACK_REG_PATTERN.match(op_str.lstrip()):
        return op_str, 0
    return _STACK_IMM_PATTERN.subn("STACK_IMM", op_str)


def _normalize_instructions(disasm_instructions) -> tuple[str, dict]:
    """
    Normalize disassembled instructions for hashing.

    Replaces absolute address operands with a placeholder while keeping
    opcodes and register names intact. Stack-pointer arithmetic immediates
    are collapsed to ``STACK_IMM`` so prologue frame-size differences do
    not fragment otherwise-identical inlined clones.

    Args:
        disasm_instructions: Iterable of capstone instruction objects

    Returns:
        Tuple of (normalized_string, stats_dict)
    """
    normalized_parts = []
    stats = {"total_instructions": 0, "operands_normalized": 0}

    # Pattern to match hex addresses (0x followed by 4+ hex digits)
    addr_pattern = re.compile(r"0x[0-9a-fA-F]{4,}")

    for insn in disasm_instructions:
        stats["total_instructions"] += 1
        op_str = insn.op_str

        # Collapse stack-pointer arithmetic immediates first so frame-size
        # variance hashes identically across inlined clones.
        op_str, stack_count = _normalize_stack_imm(insn.mnemonic, op_str)
        stats["operands_normalized"] += stack_count

        # Normalize absolute address operands to ADDR placeholder
        normalized_op, count = addr_pattern.subn("ADDR", op_str)
        stats["operands_normalized"] += count

        normalized_parts.append(f"{insn.mnemonic} {normalized_op}".strip())

    normalized_string = "\n".join(normalized_parts)
    return normalized_string, stats


def _compute_function_hash(reader, cs_arch, cs_mode, func: dict) -> dict | None:
    """
    Compute normalized opcode hash for a single function.

    Args:
        reader: BinaryReader instance (already opened)
        cs_arch: Capstone architecture constant
        cs_mode: Capstone mode constant
        func: Function dict from cache (must have basic_blocks)

    Returns:
        Dict with hash, instruction_count, stats or None on failure
    """
    import capstone

    basic_blocks = func.get("basic_blocks", [])
    if not basic_blocks:
        return None

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False

    all_instructions = []

    for block in basic_blocks:
        start_str = block.get("start", "")
        end_str = block.get("end", "")
        if not start_str or not end_str:
            continue

        try:
            start_addr = int(start_str, 16) if isinstance(start_str, str) else int(start_str)
            end_addr = int(end_str, 16) if isinstance(end_str, str) else int(end_str)
        except (ValueError, TypeError):
            continue

        block_size = end_addr - start_addr + 1
        if block_size <= 0 or block_size > 0x100000:  # 1MB sanity limit
            continue

        raw_bytes = reader.read_bytes_at_va(start_addr, block_size)
        if raw_bytes is None:
            continue

        instructions = list(md.disasm(raw_bytes, start_addr))
        all_instructions.extend(instructions)

    if not all_instructions:
        return None

    normalized_str, stats = _normalize_instructions(all_instructions)
    hash_value = hashlib.sha256(normalized_str.encode("utf-8")).hexdigest()

    return {
        "hash": hash_value,
        "instruction_count": stats["total_instructions"],
        "operands_normalized": stats["operands_normalized"],
    }


def _cluster_functions_by_hash(
    hashed_funcs: list,
    min_cluster_size: int,
    min_instructions: int,
) -> list:
    """
    Bucket hashed functions by hash and emit clone-family records.

    Buckets with fewer than ``min_cluster_size`` members are dropped, as are
    buckets whose representative instruction count falls below
    ``min_instructions``. Each surviving bucket produces a cluster record
    with sorted-by-address members, the unioned set of called API names,
    and the first member's cached pseudocode as a representative dump.

    Args:
        hashed_funcs: List of dicts each containing keys ``hash``,
            ``instruction_count``, and ``func`` (raw cached function dict).
        min_cluster_size: Minimum number of members for a bucket to count.
        min_instructions: Minimum instruction count per cluster.

    Returns:
        List of cluster dicts sorted largest-first. Each cluster has keys:
        ``hash``, ``cluster_size``, ``instruction_count``,
        ``representative_address``, ``representative_pseudocode``,
        ``members`` (sorted-by-address list of {address, name}), and
        ``called_apis`` (sorted union across members).
    """
    buckets: dict[str, list[dict]] = {}
    for entry in hashed_funcs:
        buckets.setdefault(entry["hash"], []).append(entry)

    clusters: list[dict] = []
    for hash_value, entries in buckets.items():
        if len(entries) < min_cluster_size:
            continue
        instruction_count = entries[0]["instruction_count"]
        if instruction_count < min_instructions:
            continue

        members_sorted = sorted(
            entries,
            key=lambda e: (
                e["func"].get("address") or "",
                e["func"].get("name") or "",
            ),
        )

        called_apis: set[str] = set()
        for member in entries:
            for called in member["func"].get("called_functions", []) or []:
                name = called.get("name")
                if name:
                    called_apis.add(name)

        rep = members_sorted[0]
        clusters.append(
            {
                "hash": hash_value,
                "cluster_size": len(entries),
                "instruction_count": instruction_count,
                "representative_address": rep["func"].get("address", ""),
                "representative_pseudocode": rep["func"].get("pseudocode") or "",
                "members": [
                    {
                        "address": m["func"].get("address", ""),
                        "name": m["func"].get("name", ""),
                    }
                    for m in members_sorted
                ],
                "called_apis": sorted(called_apis),
            }
        )

    clusters.sort(key=lambda c: (-c["cluster_size"], -c["instruction_count"], c["hash"]))
    return clusters


def _lookup_function(functions: list, name_or_address: str) -> dict | None:
    """
    Look up a function by exact name or address from the cached function list.

    Args:
        functions: List of function dicts from cache
        name_or_address: Function name or hex address (with or without 0x prefix)

    Returns:
        Function dict or None
    """
    # Try exact name match first
    func = next((f for f in functions if f.get("name") == name_or_address), None)
    if func:
        return func

    # Try address match (normalize both sides)
    addr_input = name_or_address.lower().replace("0x", "").lstrip("0") or "0"
    for f in functions:
        f_addr = (f.get("address", "") or "").lower().replace("0x", "").lstrip("0") or "0"
        if f_addr == addr_input:
            return f

    return None


def register_function_hash_tools(app, session_manager, cache, runner):
    """
    Register function hash, batch, and comparison tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Session manager for logging
        cache: ProjectCache instance for accessing cached analysis data
        runner: GhidraRunner instance (unused here but kept for interface consistency)
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    @app.tool()
    def get_function_hash(binary_path: str, function_name_or_address: str) -> str:
        """
        Compute a normalized opcode hash of a function for cross-binary identification.

        Disassembles the function's basic blocks with capstone, normalizes by replacing
        absolute address operands with placeholders (keeping opcodes and register names),
        then hashes the result with SHA-256. This enables matching the "same" function
        across different builds or versions of a binary where only addresses differ.

        Args:
            binary_path: Path to an already-analyzed binary
            function_name_or_address: Function name (e.g. "main") or hex address (e.g. "0x401000")

        Returns:
            Hash value, function name, address, instruction count, and normalization stats

        Example:
            get_function_hash("/path/to/binary.exe", "main")
            get_function_hash("/path/to/binary.exe", "0x00401000")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))

            cached = cache.get_cached(binary_path)
            if not cached:
                return "Error: Binary has not been analyzed yet. Run analyze_binary first."

            functions = cached.get("functions", [])
            func = _lookup_function(functions, function_name_or_address)

            if not func:
                # Try fuzzy name match for helpful suggestions
                matches = [
                    f
                    for f in functions
                    if function_name_or_address.lower() in f.get("name", "").lower()
                ]
                if matches:
                    suggestions = ", ".join(f.get("name", "") for f in matches[:5])
                    return (
                        f"Error: Function '{function_name_or_address}' not found. "
                        f"Did you mean: {suggestions}?"
                    )
                return f"Error: Function '{function_name_or_address}' not found"

            if func.get("is_thunk") or func.get("is_external"):
                return (
                    f"Error: Function '{func.get('name')}' is a "
                    f"{'thunk' if func.get('is_thunk') else 'external'} function "
                    f"and has no local code to hash."
                )

            mode = _get_capstone_mode(binary_path)
            if mode is None:
                return (
                    f"Error: Unsupported architecture for '{func.get('name')}'. "
                    f"Cannot determine capstone mode for disassembly."
                )

            cs_arch, cs_mode = mode

            from src.utils.binary_reader import BinaryReader

            with BinaryReader(binary_path) as reader:
                result = _compute_function_hash(reader, cs_arch, cs_mode, func)
            if result is None:
                return (
                    f"Error: Could not compute hash for '{func.get('name')}'. "
                    f"The function may have no basic blocks or the binary format "
                    f"is not supported for disassembly."
                )

            output = []
            output.append("=" * 60)
            output.append("FUNCTION OPCODE HASH")
            output.append("=" * 60)
            output.append(f"Function: {func.get('name')}")
            output.append(f"Address:  {func.get('address')}")
            output.append(f"SHA-256:  {result['hash']}")
            output.append("")
            output.append("Disassembly Stats:")
            output.append(f"  Instructions:        {result['instruction_count']}")
            output.append(f"  Operands normalized: {result['operands_normalized']}")
            output.append(f"  Basic blocks:        {len(func.get('basic_blocks', []))}")
            output.append("")
            output.append(
                "Note: This hash normalizes absolute addresses to enable "
                "cross-binary matching. Two functions with the same hash "
                "have identical logic regardless of where they are loaded."
            )

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("get_function_hash", e)
        except ImportError as e:
            logger.error(f"get_function_hash missing library: {e}")
            return safe_error_message("Required library not available for function hashing", e)
        except Exception as e:
            logger.error(f"get_function_hash failed: {e}")
            return safe_error_message("Failed to compute function hash", e)

    @app.tool()
    def batch_decompile(binary_path: str, functions: str) -> str:
        """
        Decompile multiple functions in a single call to reduce MCP round trips.

        Retrieves cached pseudocode for up to 20 functions at once. The binary
        must already be analyzed with analyze_binary.

        Args:
            binary_path: Path to an already-analyzed binary
            functions: Comma-separated list of function names or addresses
                       (e.g. "main,sub_401000,0x402000")

        Returns:
            Concatenated decompilation results with headers for each function

        Example:
            batch_decompile("/path/to/binary.exe", "main,entry,_init")
            batch_decompile("/path/to/binary.exe", "0x401000,0x402000,0x403000")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))

            cached = cache.get_cached(binary_path)
            if not cached:
                return "Error: Binary has not been analyzed yet. Run analyze_binary first."

            all_functions = cached.get("functions", [])

            # Parse the comma-separated function list
            requested = [f.strip() for f in functions.split(",") if f.strip()]

            if not requested:
                return "Error: No functions specified. Provide a comma-separated list."

            if len(requested) > MAX_BATCH_SIZE:
                return (
                    f"Error: Too many functions requested ({len(requested)}). "
                    f"Maximum is {MAX_BATCH_SIZE} per batch."
                )

            output = []
            output.append("=" * 60)
            output.append(f"BATCH DECOMPILATION ({len(requested)} functions)")
            output.append("=" * 60)
            output.append("")

            succeeded = 0
            failed = 0

            for func_ref in requested:
                func = _lookup_function(all_functions, func_ref)

                if not func:
                    output.append(f"--- {func_ref} ---")
                    output.append("Error: Function not found")
                    output.append("")
                    failed += 1
                    continue

                name = func.get("name", func_ref)
                address = func.get("address", "unknown")
                pseudocode = func.get("pseudocode")

                output.append(f"--- {name} @ {address} ---")

                if pseudocode:
                    signature = func.get("signature", "")
                    if signature:
                        output.append(f"Signature: {signature}")
                    output.append("")
                    output.append(pseudocode)
                    succeeded += 1
                elif func.get("is_thunk"):
                    output.append("(thunk function - no pseudocode)")
                    failed += 1
                elif func.get("is_external"):
                    output.append("(external function - no pseudocode)")
                    failed += 1
                else:
                    status = func.get("decompile_status", "unknown")
                    output.append(f"(decompilation not available - status: {status})")
                    failed += 1

                output.append("")

            output.append("=" * 60)
            output.append(f"Summary: {succeeded} succeeded, {failed} failed")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("batch_decompile", e)
        except Exception as e:
            logger.error(f"batch_decompile failed: {e}")
            return safe_error_message("Failed to batch decompile", e)

    @app.tool()
    def analyze_function_completeness(
        binary_path: str,
        function_name_or_address: str,
    ) -> str:
        """
        Score how well-analyzed a function is on a 0-100 scale.

        Evaluates multiple quality indicators including naming, decompilation,
        parameter typing, variable naming, cross-references, and size to
        produce an overall completeness score with actionable improvement tips.

        Args:
            binary_path: Path to an already-analyzed binary
            function_name_or_address: Function name or hex address

        Returns:
            Completeness score (0-100), point breakdown, and improvement suggestions

        Example:
            analyze_function_completeness("/path/to/binary.exe", "main")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))

            cached = cache.get_cached(binary_path)
            if not cached:
                return "Error: Binary has not been analyzed yet. Run analyze_binary first."

            all_functions = cached.get("functions", [])
            func = _lookup_function(all_functions, function_name_or_address)

            if not func:
                matches = [
                    f
                    for f in all_functions
                    if function_name_or_address.lower() in f.get("name", "").lower()
                ]
                if matches:
                    suggestions = ", ".join(f.get("name", "") for f in matches[:5])
                    return (
                        f"Error: Function '{function_name_or_address}' not found. "
                        f"Did you mean: {suggestions}?"
                    )
                return f"Error: Function '{function_name_or_address}' not found"

            name = func.get("name", "")
            score = 0
            breakdown = []
            suggestions = []

            # --- Scoring criteria ---

            # 1. Meaningful name (+20)
            auto_name_patterns = re.compile(
                r"^(FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+|thunk_|_?unnamed_|func_[0-9]+)$",
                re.IGNORECASE,
            )
            if name and not auto_name_patterns.match(name):
                score += 20
                breakdown.append("[+20] Has meaningful name")
            else:
                breakdown.append("[ +0] Auto-generated name")
                suggestions.append("Rename function to reflect its purpose")

            # 2. Has pseudocode (+15)
            if func.get("pseudocode"):
                score += 15
                breakdown.append("[+15] Has decompiled pseudocode")
            else:
                breakdown.append("[ +0] No pseudocode available")
                status = func.get("decompile_status", "unknown")
                if status in ("timeout", "thread_timeout", "internal_timeout"):
                    suggestions.append("Decompilation timed out - function may have anti-analysis")
                else:
                    suggestions.append("Try re-analyzing with longer timeout")

            # 3. Parameters have types (+15)
            params = func.get("parameters", [])
            if params:
                typed_params = [
                    p
                    for p in params
                    if p.get("datatype") and "undefined" not in p.get("datatype", "").lower()
                ]
                if len(typed_params) == len(params):
                    score += 15
                    breakdown.append(f"[+15] All {len(params)} parameters have types")
                elif typed_params:
                    partial = int(15 * len(typed_params) / len(params))
                    score += partial
                    breakdown.append(
                        f"[+{partial:2d}] {len(typed_params)}/{len(params)} parameters have types"
                    )
                    suggestions.append("Set types for remaining undefined parameters")
                else:
                    breakdown.append("[ +0] No parameter types defined")
                    suggestions.append("Define parameter types for better analysis")
            else:
                # No parameters could be fine (void function)
                score += 15
                breakdown.append("[+15] No parameters (void)")

            # 4. Local variables have meaningful names (+10)
            local_vars = func.get("local_variables", [])
            if local_vars:
                auto_var_pattern = re.compile(
                    r"^(local_[0-9a-fA-F]+|var_[0-9a-fA-F]+|[a-z]Var[0-9]+|"
                    r"uVar[0-9]+|iVar[0-9]+|lVar[0-9]+|pvVar[0-9]+|"
                    r"pcVar[0-9]+|puVar[0-9]+|in_[A-Z]+|Stack.*|param_[0-9]+)$"
                )
                named_vars = [
                    v for v in local_vars if v.get("name") and not auto_var_pattern.match(v["name"])
                ]
                if len(named_vars) >= len(local_vars) * 0.5 and local_vars:
                    score += 10
                    breakdown.append(
                        f"[+10] {len(named_vars)}/{len(local_vars)} variables have meaningful names"
                    )
                elif named_vars:
                    partial = int(10 * len(named_vars) / len(local_vars))
                    score += partial
                    breakdown.append(
                        f"[+{partial:2d}] {len(named_vars)}/{len(local_vars)} "
                        f"variables have meaningful names"
                    )
                    suggestions.append("Rename auto-generated local variables")
                else:
                    breakdown.append("[ +0] All variables have auto-generated names")
                    suggestions.append("Rename local variables to reflect their purpose")
            else:
                score += 10
                breakdown.append("[+10] No local variables")

            # 5. Has callers - not orphaned (+10)
            # Check if any other function calls this one
            func_name = func.get("name")
            func_addr = func.get("address", "")
            has_callers = False
            for other_func in all_functions:
                if other_func.get("name") == func_name:
                    continue
                for called in other_func.get("called_functions", []):
                    if called.get("name") == func_name or called.get("address") == func_addr:
                        has_callers = True
                        break
                if has_callers:
                    break

            if has_callers:
                score += 10
                breakdown.append("[+10] Has callers (referenced)")
            else:
                breakdown.append("[ +0] No callers found (orphaned or entry point)")
                if name not in ("main", "entry", "_start", "DllMain", "WinMain"):
                    suggestions.append(
                        "Function appears unreferenced - may be dead code or indirect call target"
                    )

            # 6. Has callees (+5)
            called_functions = func.get("called_functions", [])
            if called_functions:
                score += 5
                breakdown.append(f"[ +5] Calls {len(called_functions)} function(s)")
            else:
                breakdown.append("[ +0] Leaf function (no calls)")

            # 7. Reasonable size (+5)
            basic_blocks = func.get("basic_blocks", [])
            total_addresses = sum(b.get("num_addresses", 0) for b in basic_blocks)
            if 4 < total_addresses < 50000:
                score += 5
                breakdown.append(f"[ +5] Reasonable size ({total_addresses} addresses)")
            elif total_addresses <= 4:
                breakdown.append(
                    f"[ +0] Very small ({total_addresses} addresses) - may be thunk/stub"
                )
                suggestions.append("Very small function - may be a thunk or wrapper")
            else:
                breakdown.append(f"[ +0] Very large ({total_addresses} addresses)")
                suggestions.append("Very large function - consider splitting analysis")

            # 8. Has basic blocks extracted (+5)
            if basic_blocks:
                score += 5
                breakdown.append(f"[ +5] {len(basic_blocks)} basic block(s) extracted")
            else:
                breakdown.append("[ +0] No basic blocks")
                suggestions.append("Basic block extraction failed")

            # --- Deductions ---

            # Auto-generated name deduction (-10)
            if auto_name_patterns.match(name):
                score = max(0, score - 10)
                breakdown.append("[-10] Penalty: auto-generated name")

            # Missing signature (-10)
            signature = func.get("signature", "")
            if not signature or signature == "undefined":
                score = max(0, score - 10)
                breakdown.append("[-10] Penalty: missing/invalid signature")
                suggestions.append("Define the function signature")

            # No xrefs at all (-5)
            if not has_callers and not called_functions:
                score = max(0, score - 5)
                breakdown.append("[ -5] Penalty: no cross-references")

            # Clamp score
            score = max(0, min(100, score))

            # Determine grade
            if score >= 80:
                grade = "EXCELLENT"
            elif score >= 60:
                grade = "GOOD"
            elif score >= 40:
                grade = "FAIR"
            elif score >= 20:
                grade = "POOR"
            else:
                grade = "MINIMAL"

            output = []
            output.append("=" * 60)
            output.append("FUNCTION COMPLETENESS ANALYSIS")
            output.append("=" * 60)
            output.append(f"Function: {name}")
            output.append(f"Address:  {func.get('address')}")
            output.append(f"Score:    {score}/100 ({grade})")
            output.append("")
            output.append("Point Breakdown:")
            for line in breakdown:
                output.append(f"  {line}")
            output.append("")

            if suggestions:
                output.append("Improvement Suggestions:")
                for i, suggestion in enumerate(suggestions, 1):
                    output.append(f"  {i}. {suggestion}")
            else:
                output.append("No improvement suggestions - function is well-analyzed.")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("analyze_function_completeness", e)
        except Exception as e:
            logger.error(f"analyze_function_completeness failed: {e}")
            return safe_error_message("Failed to analyze function completeness", e)

    @app.tool()
    def find_similar_functions(
        binary_path: str,
        target_binary_path: str,
        threshold: float = 0.7,
    ) -> str:
        """
        Find matching functions between two analyzed binaries using normalized opcode hashes.

        Computes normalized opcode hashes for all functions in both binaries and
        identifies exact matches (same hash). For non-exact matches, uses a simplified
        fuzzy comparison based on function size, call count, and called function overlap.

        Both binaries must already be analyzed with analyze_binary.

        Args:
            binary_path: Path to the first (source) analyzed binary
            target_binary_path: Path to the second (target) analyzed binary
            threshold: Minimum similarity score (0.0-1.0) for fuzzy matches (default: 0.7)

        Returns:
            List of matched function pairs with similarity scores

        Example:
            find_similar_functions("/path/to/v1.exe", "/path/to/v2.exe")
            find_similar_functions("/path/to/v1.exe", "/path/to/v2.exe", threshold=0.8)
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))
            target_binary_path = str(sanitize_binary_path(target_binary_path))

            if threshold < 0.0 or threshold > 1.0:
                return "Error: Threshold must be between 0.0 and 1.0"

            cached_a = cache.get_cached(binary_path)
            if not cached_a:
                return (
                    f"Error: Source binary has not been analyzed yet. "
                    f"Run analyze_binary on {Path(binary_path).name} first."
                )

            cached_b = cache.get_cached(target_binary_path)
            if not cached_b:
                return (
                    f"Error: Target binary has not been analyzed yet. "
                    f"Run analyze_binary on {Path(target_binary_path).name} first."
                )

            funcs_a = [
                f
                for f in cached_a.get("functions", [])
                if not f.get("is_thunk") and not f.get("is_external") and f.get("basic_blocks")
            ]
            funcs_b = [
                f
                for f in cached_b.get("functions", [])
                if not f.get("is_thunk") and not f.get("is_external") and f.get("basic_blocks")
            ]

            if not funcs_a:
                return f"Error: No hashable functions found in {Path(binary_path).name}"
            if not funcs_b:
                return f"Error: No hashable functions found in {Path(target_binary_path).name}"

            from bisect import bisect_left, bisect_right

            from src.utils.binary_reader import BinaryReader

            # Detect capstone mode once per binary
            mode_a = _get_capstone_mode(binary_path)
            if mode_a is None:
                return f"Error: Unsupported architecture for {Path(binary_path).name}"
            mode_b = _get_capstone_mode(target_binary_path)
            if mode_b is None:
                return f"Error: Unsupported architecture for {Path(target_binary_path).name}"

            cs_arch_a, cs_mode_a = mode_a
            cs_arch_b, cs_mode_b = mode_b

            # Compute hashes for source binary (one reader open)
            hashes_a = {}
            with BinaryReader(binary_path) as reader_a:
                for func in funcs_a:
                    result = _compute_function_hash(reader_a, cs_arch_a, cs_mode_a, func)
                    if result:
                        hashes_a[func.get("name")] = {
                            "hash": result["hash"],
                            "instruction_count": result["instruction_count"],
                            "called_functions": frozenset(
                                c.get("name", "") for c in func.get("called_functions", [])
                            ),
                            "func": func,
                        }

            # Compute hashes for target binary (one reader open)
            hashes_b = {}
            with BinaryReader(target_binary_path) as reader_b:
                for func in funcs_b:
                    result = _compute_function_hash(reader_b, cs_arch_b, cs_mode_b, func)
                    if result:
                        hashes_b[func.get("name")] = {
                            "hash": result["hash"],
                            "instruction_count": result["instruction_count"],
                            "called_functions": frozenset(
                                c.get("name", "") for c in func.get("called_functions", [])
                            ),
                            "func": func,
                        }

            if not hashes_a:
                return f"Error: Could not hash any functions in {Path(binary_path).name}"
            if not hashes_b:
                return f"Error: Could not hash any functions in {Path(target_binary_path).name}"

            # Find exact matches
            exact_matches = []
            hash_to_b = {}
            for name_b, info_b in hashes_b.items():
                hash_to_b.setdefault(info_b["hash"], []).append(name_b)

            matched_b_names = set()
            matched_a_names = set()

            for name_a, info_a in hashes_a.items():
                if info_a["hash"] in hash_to_b:
                    for name_b in hash_to_b[info_a["hash"]]:
                        if name_b not in matched_b_names:
                            exact_matches.append((name_a, name_b, 1.0))
                            matched_a_names.add(name_a)
                            matched_b_names.add(name_b)
                            break

            # Fuzzy matching for remaining functions -- use bisect for size windowing
            fuzzy_matches = []
            remaining_a = {n: v for n, v in hashes_a.items() if n not in matched_a_names}
            remaining_b = {n: v for n, v in hashes_b.items() if n not in matched_b_names}

            # Sort remaining_b by instruction count for binary search windowing
            sorted_b = sorted(
                remaining_b.items(),
                key=lambda x: x[1]["instruction_count"],
            )
            sorted_b_counts = [info["instruction_count"] for _, info in sorted_b]

            comparison_count = 0
            for name_a, info_a in remaining_a.items():
                ic_a = info_a["instruction_count"]
                # Only compare with functions within 50% instruction count
                lo = bisect_left(sorted_b_counts, int(ic_a * 0.5))
                hi = bisect_right(sorted_b_counts, int(ic_a * 1.5))

                best_score = 0.0
                best_match = None

                for idx in range(lo, hi):
                    name_b, info_b = sorted_b[idx]
                    if name_b in matched_b_names:
                        continue

                    comparison_count += 1
                    if comparison_count > MAX_FUZZY_COMPARISONS:
                        break

                    # Size similarity (instruction count)
                    ic_b = info_b["instruction_count"]
                    max_ic = max(ic_a, ic_b)
                    size_sim = 1.0 - (abs(ic_a - ic_b) / max_ic) if max_ic > 0 else 1.0

                    # Call count similarity
                    cc_a = len(info_a["called_functions"])
                    cc_b = len(info_b["called_functions"])
                    max_cc = max(cc_a, cc_b)
                    call_sim = 1.0 - (abs(cc_a - cc_b) / max_cc) if max_cc > 0 else 1.0

                    # Called function name overlap (import overlap) -- pre-computed frozensets
                    set_a = info_a["called_functions"]
                    set_b = info_b["called_functions"]
                    if set_a and set_b:
                        overlap = len(set_a & set_b)
                        union = len(set_a | set_b)
                        import_sim = overlap / union if union > 0 else 0.0
                    elif not set_a and not set_b:
                        import_sim = 1.0
                    else:
                        import_sim = 0.0

                    # Weighted combination
                    similarity = (size_sim * 0.4) + (call_sim * 0.2) + (import_sim * 0.4)

                    if similarity > best_score:
                        best_score = similarity
                        best_match = name_b

                if comparison_count > MAX_FUZZY_COMPARISONS:
                    break

                if best_match and best_score >= threshold:
                    fuzzy_matches.append((name_a, best_match, best_score))
                    matched_b_names.add(best_match)

            # Sort fuzzy matches by score descending
            fuzzy_matches.sort(key=lambda x: x[2], reverse=True)

            # Format output
            output = []
            output.append("=" * 60)
            output.append("CROSS-BINARY FUNCTION MATCHING")
            output.append("=" * 60)
            output.append(f"Source: {Path(binary_path).name} ({len(hashes_a)} hashable functions)")
            output.append(
                f"Target: {Path(target_binary_path).name} ({len(hashes_b)} hashable functions)"
            )
            output.append(f"Threshold: {threshold:.0%}")
            output.append("")

            if exact_matches:
                output.append(f"Exact Matches ({len(exact_matches)}):")
                output.append("-" * 40)
                for name_a, name_b, score in exact_matches:
                    addr_a = hashes_a[name_a]["func"].get("address", "?")
                    addr_b = hashes_b[name_b]["func"].get("address", "?")
                    output.append(f"  {name_a} ({addr_a})  <->  {name_b} ({addr_b})  [100%]")
                output.append("")

            if fuzzy_matches:
                output.append(f"Fuzzy Matches ({len(fuzzy_matches)}):")
                output.append("-" * 40)
                for name_a, name_b, score in fuzzy_matches:
                    addr_a = hashes_a[name_a]["func"].get("address", "?")
                    addr_b = hashes_b[name_b]["func"].get("address", "?")
                    output.append(f"  {name_a} ({addr_a})  <->  {name_b} ({addr_b})  [{score:.0%}]")
                output.append("")

            total = len(exact_matches) + len(fuzzy_matches)
            if total == 0:
                output.append("No matching functions found above threshold.")
            else:
                output.append(
                    f"Total: {total} matches ({len(exact_matches)} exact, {len(fuzzy_matches)} fuzzy)"
                )

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("find_similar_functions", e)
        except ImportError as e:
            logger.error(f"find_similar_functions missing library: {e}")
            return safe_error_message("Required library not available for function comparison", e)
        except Exception as e:
            logger.error(f"find_similar_functions failed: {e}")
            return safe_error_message("Failed to find similar functions", e)

    @app.tool()
    def find_inlined_clones(
        binary_path: str,
        min_cluster_size: int = 3,
        min_instructions: int = 10,
    ) -> str:
        """
        Detect intra-binary clusters of inlined function clones.

        Compilers frequently inline helpers like memcpy/strlen/refcount
        adjusters and crypto round functions, leaving large binaries with
        hundreds of opcode-identical bodies named ``FUN_*``. This tool reuses
        the normalized opcode hash from get_function_hash to bucket cached
        functions in a single binary into clone families, so you can name
        one canonical example and review siblings together.

        The hash collapses absolute addresses and stack-pointer arithmetic
        immediates, so frame-size variance between inlined copies does not
        fragment otherwise-identical clusters.

        LIMITATION: link-time-optimised or ICF-deduplicated builds may
        produce zero exact-hash clusters because the linker has already
        merged duplicates. Such binaries are healthier candidates for fuzzy
        matching via find_similar_functions.

        The binary must already be analyzed with analyze_binary; this tool
        is cache-only and does not invoke Ghidra.

        Args:
            binary_path: Path to an already-analyzed binary
            min_cluster_size: Minimum number of clone members per family
                (default: 3, must be >= 2)
            min_instructions: Minimum normalized instruction count per
                cluster (default: 10, must be >= 1)

        Returns:
            Sorted clone-family report with representative pseudocode,
            member addresses, called-API set, and cluster size for each
            family. Clusters are ranked largest-first.

        Example:
            find_inlined_clones("/path/to/binary.exe")
            find_inlined_clones("/path/to/binary.exe", min_cluster_size=5)

        Note:
            Bulk-rename of a clone family is not yet implemented; rename one
            representative per cluster manually.
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))

            if min_cluster_size < 2:
                return "Error: min_cluster_size must be >= 2"
            if min_instructions < 1:
                return "Error: min_instructions must be >= 1"

            cached = cache.get_cached(binary_path)
            if not cached:
                return "Error: Binary has not been analyzed yet. Run analyze_binary first."

            funcs = [
                f
                for f in cached.get("functions", [])
                if not f.get("is_thunk") and not f.get("is_external") and f.get("basic_blocks")
            ]

            if not funcs:
                return f"Error: No hashable functions found in {Path(binary_path).name}"

            mode = _get_capstone_mode(binary_path)
            if mode is None:
                return f"Error: Unsupported architecture for {Path(binary_path).name}"
            cs_arch, cs_mode = mode

            from src.utils.binary_reader import BinaryReader

            hashed: list[dict] = []
            with BinaryReader(binary_path) as reader:
                for func in funcs:
                    result = _compute_function_hash(reader, cs_arch, cs_mode, func)
                    if result is None:
                        continue
                    hashed.append(
                        {
                            "hash": result["hash"],
                            "instruction_count": result["instruction_count"],
                            "func": func,
                        }
                    )

            if not hashed:
                return f"Error: Could not hash any functions in {Path(binary_path).name}"

            clusters = _cluster_functions_by_hash(hashed, min_cluster_size, min_instructions)

            output = []
            output.append("=" * 60)
            output.append("INTRA-BINARY INLINED CLONE FAMILIES")
            output.append("=" * 60)
            output.append(f"Binary:             {Path(binary_path).name}")
            output.append(f"Functions scanned:  {len(funcs)}")
            output.append(f"Functions hashed:   {len(hashed)}")
            output.append(f"min_cluster_size:   {min_cluster_size}")
            output.append(f"min_instructions:   {min_instructions}")
            total_members = sum(c["cluster_size"] for c in clusters)
            output.append(f"Clusters found:     {len(clusters)} ({total_members} total members)")
            output.append("")

            if not clusters:
                output.append(
                    "No clone families detected. This is normal on LTO/ICF "
                    "builds where the linker has already merged identical "
                    "bodies. Try find_similar_functions for fuzzy "
                    "intra-binary matching."
                )
                return "\n".join(output)

            for idx, cluster in enumerate(clusters, 1):
                output.append("-" * 60)
                output.append(
                    f"Cluster #{idx}  -  size={cluster['cluster_size']}, "
                    f"instructions={cluster['instruction_count']}"
                )
                output.append(f"Hash: {cluster['hash']}")
                output.append("")
                output.append("Members:")
                for member in cluster["members"]:
                    output.append(f"  {member['address']}  {member['name']}")
                output.append("")
                if cluster["called_apis"]:
                    output.append(
                        f"Called APIs ({len(cluster['called_apis'])}): "
                        + ", ".join(cluster["called_apis"])
                    )
                else:
                    output.append("Called APIs: (leaf body)")
                output.append("")
                pseudocode = cluster["representative_pseudocode"]
                if pseudocode:
                    output.append(
                        f"Representative pseudocode (from {cluster['representative_address']}):"
                    )
                    output.append(pseudocode)
                else:
                    output.append("(no pseudocode available for representative)")
                output.append("")

            output.append("=" * 60)
            output.append(
                "Tip: rename one representative per cluster, then review "
                "remaining members. Bulk-rename helper not yet implemented."
            )
            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("find_inlined_clones", e)
        except ImportError as e:
            logger.error(f"find_inlined_clones missing library: {e}")
            return safe_error_message("Required library not available for clone detection", e)
        except Exception as e:
            logger.error(f"find_inlined_clones failed: {e}")
            return safe_error_message("Failed to find inlined clones", e)

    logger.info("Registered 5 function hash tools")
