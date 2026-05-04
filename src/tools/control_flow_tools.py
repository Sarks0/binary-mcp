"""
Control flow analysis tools for binary reverse engineering.

Provides CFG construction, loop detection, dead code analysis,
and complexity metrics using cached Ghidra analysis data and
capstone disassembly.
"""

import logging
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


# --- Internal helpers ---


def _get_or_run_analysis(binary_path: str, cache, runner) -> dict:
    """
    Return cached analysis data for *binary_path*, running Ghidra first if
    no cache exists yet.

    This mirrors the pattern used by ``get_analysis_context`` in server.py
    but is self-contained so the tool module does not import the server.

    Args:
        binary_path: Validated path to binary file
        cache: ProjectCache instance
        runner: GhidraRunner instance

    Returns:
        Analysis context dict (functions, metadata, memory_map, …)

    Raises:
        RuntimeError: If analysis fails
    """
    cached = cache.get_cached(str(binary_path))
    if cached:
        return cached

    # Need to run Ghidra analysis
    from src.utils.config import get_config_int
    from src.utils.security import validate_numeric_range

    output_path = cache.cache_dir / f"temp_analysis_{Path(binary_path).stem}.json"
    script_path = Path(__file__).parent.parent / "engines" / "static" / "ghidra" / "scripts"

    timeout = get_config_int("GHIDRA_TIMEOUT", 600)
    timeout = validate_numeric_range(timeout, 30, 3600, "GHIDRA_TIMEOUT")

    import json

    runner.analyze(
        binary_path=str(binary_path),
        script_path=str(script_path),
        script_name="core_analysis.py",
        output_path=str(output_path),
        keep_project=True,
        timeout=timeout,
    )

    if not output_path.exists():
        raise RuntimeError(
            "Ghidra did not produce output. The binary format may be unsupported."
        )

    with open(output_path, encoding="utf-8") as f:
        context = json.load(f)

    cache.save_cached(str(binary_path), context)
    output_path.unlink(missing_ok=True)
    return context


def _find_function(functions: list[dict], name_or_address: str) -> dict | None:
    """
    Look up a function by exact name, address, or fuzzy name match.

    Args:
        functions: List of function dicts from cached analysis
        name_or_address: Function name or hex address (with or without 0x)

    Returns:
        Matching function dict, or None
    """
    # Exact name match
    for f in functions:
        if f.get("name") == name_or_address:
            return f

    # Address match (normalize both sides)
    needle = name_or_address.lower().replace("0x", "").lstrip("0") or "0"
    for f in functions:
        addr = (f.get("address") or "").lower().replace("0x", "").lstrip("0") or "0"
        if addr == needle:
            return f

    # Case-insensitive substring match (first hit)
    lower_query = name_or_address.lower()
    for f in functions:
        if lower_query in (f.get("name") or "").lower():
            return f

    return None


def _suggest_functions(functions: list[dict], name_or_address: str, limit: int = 5) -> str:
    """Return a comma-separated list of similar function names."""
    lower_query = name_or_address.lower()
    matches = [
        f.get("name", "")
        for f in functions
        if lower_query in (f.get("name") or "").lower()
    ]
    if matches:
        return ", ".join(matches[:limit])
    return ""


def _parse_capstone_arch(metadata: dict):
    """
    Determine capstone architecture constants from Ghidra metadata.

    Accepts three shapes of ``language`` field for backward compatibility:
    1. Canonical Ghidra LanguageID: ``x86:LE:64:default``, ``ARM:LE:32:v7``,
       ``AARCH64:LE:64:v8A`` (current format).
    2. Description string from ``Language.toString()`` - older caches stored
       this instead of the canonical ID. Parsed by keyword.
    3. Empty / unparseable - falls through to ``executable_format`` keyword
       inspection so PE/ELF-64 binaries still get x86-64 disassembly.

    Returns:
        Tuple of (cs_arch, cs_mode) or (None, None) if unsupported.
    """
    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_ARCH_ARM64,
            CS_ARCH_X86,
            CS_MODE_32,
            CS_MODE_64,
            CS_MODE_ARM,
            CS_MODE_LITTLE_ENDIAN,
        )
    except ImportError:
        return None, None

    lang = str(metadata.get("language", "")).upper()

    # --- Path 1: canonical colon-delimited ID -----------------------------
    parts = lang.split(":")
    if len(parts) >= 3:
        processor = parts[0]
        bitness_str = parts[2]
        if processor == "X86":
            mode = CS_MODE_64 if bitness_str == "64" else CS_MODE_32
            return CS_ARCH_X86, mode
        if processor == "ARM" and bitness_str == "32":
            return CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN
        if processor in ("AARCH64", "ARM") and bitness_str == "64":
            return CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

    # --- Path 2: description keyword match --------------------------------
    # Covers Ghidra Language.toString() output plus older caches where the
    # field was a mix of language info.
    haystack = " ".join(
        str(metadata.get(k, "")) for k in ("language", "language_description")
    ).upper()
    has_64 = "64" in haystack or "X86-64" in haystack or "AMD64" in haystack

    if "AARCH64" in haystack or "ARM64" in haystack:
        return CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    if "ARM" in haystack:
        return CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN
    if "X86" in haystack or "X64" in haystack or "INTEL" in haystack:
        return CS_ARCH_X86, CS_MODE_64 if has_64 else CS_MODE_32

    # --- Path 3: executable_format fallback -------------------------------
    # If the language field is useless, try to infer from the binary format.
    # PE + 64-bit image_base >= 0x100000000 is a strong x86-64 signal.
    exe_fmt = str(metadata.get("executable_format", "")).upper()
    image_base_raw = str(metadata.get("image_base", "")).lower().replace("0x", "")
    try:
        image_base = int(image_base_raw, 16) if image_base_raw else 0
    except ValueError:
        image_base = 0

    # PE is overwhelmingly x86/x64; image_base > 4GB is the classic PE32+
    # signal for 64-bit. ELF gets no format fallback because ARM/MIPS/RISC-V
    # ELFs would be mis-detected as x86.
    if "PORTABLE EXECUTABLE" in exe_fmt or "PE " in exe_fmt or exe_fmt == "PE":
        return CS_ARCH_X86, CS_MODE_64 if image_base > 0xFFFFFFFF else CS_MODE_32

    return None, None


def _build_function_index(functions: list[dict]) -> dict:
    """
    Build O(1) lookup indexes for a function list.

    Returns:
        Dict with ``by_name`` (name -> func) and ``by_addr`` (normalized_addr -> func).
    """
    by_name: dict[str, dict] = {}
    by_addr: dict[str, dict] = {}
    for f in functions:
        name = f.get("name", "")
        if name:
            by_name[name] = f
        addr = (f.get("address") or "").lower().replace("0x", "").lstrip("0") or "0"
        by_addr[addr] = f
    return {"by_name": by_name, "by_addr": by_addr}


def _parse_address(addr_str: str) -> int:
    """Parse a hex address string (with or without 0x prefix) to int."""
    return int(str(addr_str).strip(), 16)


def _build_cfg(func: dict, reader, metadata: dict):
    """
    Build a control flow graph from a function's basic blocks by
    disassembling the last instruction of each block with capstone to
    determine successors.

    Args:
        func: Function dict from cached analysis
        reader: BinaryReader instance (already opened)
        metadata: Ghidra analysis metadata dict

    Returns:
        Tuple of (blocks, edges, entry_addr) where:
        - blocks: dict mapping start_addr -> {start, end, size, instructions}
        - edges: list of (src_addr, dst_addr)
        - entry_addr: int address of function entry
    """
    from capstone import CS_GRP_JUMP, CS_GRP_RET, Cs

    cs_arch, cs_mode = _parse_capstone_arch(metadata)
    if cs_arch is None:
        raise RuntimeError(
            "Unsupported architecture for disassembly. "
            f"Ghidra language: {metadata.get('language', 'unknown')}"
        )

    md = Cs(cs_arch, cs_mode)
    md.detail = True

    basic_blocks = func.get("basic_blocks", [])
    if not basic_blocks:
        raise RuntimeError(
            f"Function '{func.get('name')}' has no basic blocks in the cached analysis."
        )

    entry_addr = _parse_address(func["address"])

    # Parse blocks into our internal representation
    blocks: dict[int, dict] = {}
    block_starts: set[int] = set()

    for bb in basic_blocks:
        start = _parse_address(bb["start"])
        end = _parse_address(bb["end"])
        size = bb.get("num_addresses", end - start + 1)
        blocks[start] = {
            "start": start,
            "end": end,
            "size": size,
        }
        block_starts.add(start)

    # Sort blocks by address for sequential fallthrough logic
    sorted_addrs = sorted(blocks.keys())
    addr_to_idx = {a: i for i, a in enumerate(sorted_addrs)}

    edges: list[tuple[int, int]] = []

    for blk_addr in sorted_addrs:
        blk = blocks[blk_addr]
        blk_size = blk["size"]

        # Read raw bytes for the block
        raw = reader.read_bytes_at_va(blk_addr, blk_size)
        if not raw:
            # Can't disassemble - assume fallthrough to next block
            idx = addr_to_idx[blk_addr]
            if idx + 1 < len(sorted_addrs):
                edges.append((blk_addr, sorted_addrs[idx + 1]))
            continue

        # Disassemble to find the last instruction
        instructions = list(md.disasm(raw, blk_addr))
        if not instructions:
            idx = addr_to_idx[blk_addr]
            if idx + 1 < len(sorted_addrs):
                edges.append((blk_addr, sorted_addrs[idx + 1]))
            continue

        last_insn = instructions[-1]

        is_jump = any(g in last_insn.groups for g in (CS_GRP_JUMP,))
        is_ret = any(g in last_insn.groups for g in (CS_GRP_RET,))

        if is_ret:
            # No successors - function returns
            pass
        elif is_jump:
            mnemonic = last_insn.mnemonic.lower()
            # Try to parse target address from operand
            target = _parse_jump_target(last_insn)

            if target is not None and target in block_starts:
                edges.append((blk_addr, target))

            # Conditional jumps also fall through
            is_unconditional = mnemonic in (
                "jmp", "b", "br", "bx",  # x86 / ARM unconditional
            )
            if not is_unconditional:
                idx = addr_to_idx[blk_addr]
                if idx + 1 < len(sorted_addrs):
                    edges.append((blk_addr, sorted_addrs[idx + 1]))
        else:
            # Non-branch instruction at end of block → fallthrough
            idx = addr_to_idx[blk_addr]
            if idx + 1 < len(sorted_addrs):
                edges.append((blk_addr, sorted_addrs[idx + 1]))

    return blocks, edges, entry_addr


def _parse_jump_target(insn) -> int | None:
    """Try to extract a constant jump target address from a capstone instruction."""
    op_str = insn.op_str.strip()
    # Handle operands like "0x401000" or plain hex
    try:
        if op_str.startswith("0x") or op_str.startswith("0X"):
            return int(op_str, 16)
        # Some disassemblers emit just a hex number
        return int(op_str, 16)
    except (ValueError, TypeError):
        pass
    # capstone x86 immediate operand
    if hasattr(insn, "operands") and insn.operands:
        for op in insn.operands:
            if op.type == 2:  # CS_OP_IMM on x86
                return op.imm
    return None


def _find_loops(blocks: dict, edges: list[tuple[int, int]], entry_addr: int):
    """
    Detect natural loops via back-edge identification using DFS.

    A back edge is an edge (u → v) where v dominates u. For simplicity
    we use the classic DFS classification: an edge to an ancestor in the
    DFS tree is a back edge.

    Returns:
        List of dicts with keys: header, back_edge_src, body (set of addrs)
    """
    # Build adjacency list
    successors: dict[int, list[int]] = defaultdict(list)
    for src, dst in edges:
        successors[src].append(dst)

    # DFS to find back edges
    gray, black = 1, 2
    color: dict[int, int] = {}
    back_edges: list[tuple[int, int]] = []
    dfs_order: list[int] = []

    # Use iterative DFS to avoid recursion limit
    stack = [(entry_addr, 0)]
    children_map: dict[int, list[int]] = {}

    while stack:
        node, child_idx = stack[-1]
        if node not in color:
            color[node] = gray
            dfs_order.append(node)
            children_map[node] = list(successors[node])

        children = children_map.get(node, [])
        if child_idx < len(children):
            stack[-1] = (node, child_idx + 1)
            succ = children[child_idx]
            if succ not in color:
                stack.append((succ, 0))
            elif color[succ] == gray:
                back_edges.append((node, succ))
        else:
            color[node] = black
            stack.pop()

    # For each back edge, find the natural loop body
    predecessors: dict[int, list[int]] = defaultdict(list)
    for src, dst in edges:
        predecessors[dst].append(src)

    loops = []
    for tail, header in back_edges:
        # Natural loop: all nodes that can reach `tail` without going through `header`
        body = {header, tail}
        worklist = [tail] if tail != header else []
        while worklist:
            node = worklist.pop()
            for pred in predecessors[node]:
                if pred not in body:
                    body.add(pred)
                    worklist.append(pred)
        loops.append({
            "header": header,
            "back_edge_src": tail,
            "body": body,
        })

    return loops


def _compute_nesting_depth(loops: list[dict]) -> dict[int, int]:
    """
    Compute nesting depth for each loop (by header address).

    A loop A is nested inside loop B if A.body ⊂ B.body.

    Returns:
        Dict mapping loop header → nesting depth (1 = outermost)
    """
    if not loops:
        return {}

    # Sort loops by body size descending (larger loops are outer)
    sorted_loops = sorted(loops, key=lambda lp: len(lp["body"]), reverse=True)
    depths: dict[int, int] = {}

    for i, loop in enumerate(sorted_loops):
        depth = 1
        for outer in sorted_loops[:i]:
            if loop["body"] < outer["body"]:  # strict subset
                depth = max(depth, depths.get(outer["header"], 1) + 1)
        depths[loop["header"]] = depth

    return depths


# --- Public registration ---


def register_control_flow_tools(app, session_manager=None, cache=None, runner=None):
    """
    Register control-flow analysis tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
        cache: ProjectCache instance for cached analysis data
        runner: GhidraRunner instance for on-demand analysis
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    # ------------------------------------------------------------------
    # Tool 1: analyze_control_flow
    # ------------------------------------------------------------------
    @app.tool()
    def analyze_control_flow(
        binary_path: str,
        function_name_or_address: str,
    ) -> str:
        """
        Build and analyze the control flow graph (CFG) of a function.

        Disassembles basic blocks with capstone to determine branch targets,
        then computes graph metrics including cyclomatic complexity.

        Args:
            binary_path: Path to an analyzed binary
            function_name_or_address: Function name or hex address (e.g. "main" or "0x401000")

        Returns:
            Formatted CFG report with block list, edge list, and metrics

        Example:
            analyze_control_flow("/samples/malware.exe", "main")
            analyze_control_flow("/samples/malware.exe", "0x00401000")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))
            context = _get_or_run_analysis(binary_path, cache, runner)
            functions = context.get("functions", [])
            metadata = context.get("metadata", {})

            func = _find_function(functions, function_name_or_address)
            if not func:
                suggestions = _suggest_functions(functions, function_name_or_address)
                msg = f"Function '{function_name_or_address}' not found."
                if suggestions:
                    msg += f" Did you mean: {suggestions}?"
                return msg

            func_name = func.get("name", "unknown")
            func_addr = func.get("address", "?")

            from src.utils.binary_reader import BinaryReader

            try:
                with BinaryReader(binary_path) as reader:
                    blocks, edges, entry_addr = _build_cfg(func, reader, metadata)
            except RuntimeError as e:
                return f"Error building CFG for '{func_name}': {e}"

            num_blocks = len(blocks)
            num_edges = len(edges)
            # Cyclomatic complexity: M = E - N + 2P (P = 1 for single function)
            cyclomatic = num_edges - num_blocks + 2

            # Find unreachable blocks
            reachable: set[int] = set()
            worklist = [entry_addr]
            successors_map: dict[int, list[int]] = defaultdict(list)
            for src, dst in edges:
                successors_map[src].append(dst)

            while worklist:
                node = worklist.pop()
                if node in reachable:
                    continue
                reachable.add(node)
                for succ in successors_map[node]:
                    if succ not in reachable:
                        worklist.append(succ)

            unreachable = set(blocks.keys()) - reachable

            # Detect loops
            loops = _find_loops(blocks, edges, entry_addr)

            # Build output
            out = []
            out.append("=" * 70)
            out.append(f"CONTROL FLOW ANALYSIS: {func_name}")
            out.append("=" * 70)
            out.append(f"Function: {func_name} @ {func_addr}")
            out.append("")

            # Metrics
            out.append("Metrics:")
            out.append(f"  Basic blocks:          {num_blocks}")
            out.append(f"  Edges:                 {num_edges}")
            out.append(f"  Cyclomatic complexity:  {cyclomatic}")
            out.append(f"  Natural loops:         {len(loops)}")
            out.append(f"  Unreachable blocks:    {len(unreachable)}")
            out.append("")

            # Block listing
            out.append(f"Basic Blocks ({num_blocks}):")
            for addr in sorted(blocks.keys()):
                blk = blocks[addr]
                marker = ""
                if addr == entry_addr:
                    marker = " [ENTRY]"
                if addr in unreachable:
                    marker = " [UNREACHABLE]"
                out.append(
                    f"  0x{blk['start']:08x} - 0x{blk['end']:08x}  "
                    f"({blk['size']} bytes){marker}"
                )
            out.append("")

            # Edge listing (limit to 50 to avoid huge output)
            out.append(f"Edges ({num_edges}):")
            for i, (src, dst) in enumerate(sorted(edges)):
                if i >= 50:
                    out.append(f"  ... and {num_edges - 50} more edges")
                    break
                out.append(f"  0x{src:08x} -> 0x{dst:08x}")
            out.append("")

            # Loops
            if loops:
                out.append(f"Natural Loops ({len(loops)}):")
                nesting = _compute_nesting_depth(loops)
                for i, loop in enumerate(loops, 1):
                    depth = nesting.get(loop["header"], 1)
                    out.append(
                        f"  Loop {i}: header=0x{loop['header']:08x}  "
                        f"blocks={len(loop['body'])}  nesting_depth={depth}"
                    )
                out.append("")

            if unreachable:
                out.append("Unreachable Blocks:")
                for addr in sorted(unreachable):
                    out.append(f"  0x{addr:08x}")
                out.append("")

            return "\n".join(out)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("analyze_control_flow", e)
        except Exception as e:
            logger.error(f"analyze_control_flow failed: {e}")
            return safe_error_message("Failed to analyze control flow", e)

    # ------------------------------------------------------------------
    # Tool 2: detect_loops
    # ------------------------------------------------------------------
    @app.tool()
    def detect_loops(
        binary_path: str,
        function_name_or_address: str,
    ) -> str:
        """
        Detect natural loops in a function's control flow graph.

        Identifies back edges via DFS traversal and computes the natural
        loop body for each. Reports loop headers, exit points, nesting
        depth, and the blocks belonging to each loop.

        Useful for locating encryption routines, decode loops, hash
        computations, and other iterative algorithms in malware.

        Args:
            binary_path: Path to an analyzed binary
            function_name_or_address: Function name or hex address

        Returns:
            Formatted loop analysis report

        Example:
            detect_loops("/samples/malware.exe", "decrypt_payload")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))
            context = _get_or_run_analysis(binary_path, cache, runner)
            functions = context.get("functions", [])
            metadata = context.get("metadata", {})

            func = _find_function(functions, function_name_or_address)
            if not func:
                suggestions = _suggest_functions(functions, function_name_or_address)
                msg = f"Function '{function_name_or_address}' not found."
                if suggestions:
                    msg += f" Did you mean: {suggestions}?"
                return msg

            func_name = func.get("name", "unknown")
            func_addr = func.get("address", "?")

            from src.utils.binary_reader import BinaryReader

            try:
                with BinaryReader(binary_path) as reader:
                    blocks, edges, entry_addr = _build_cfg(func, reader, metadata)
            except RuntimeError as e:
                return f"Error building CFG for '{func_name}': {e}"

            loops = _find_loops(blocks, edges, entry_addr)
            nesting = _compute_nesting_depth(loops)

            # Build successor/predecessor maps for exit-point detection
            successors_map: dict[int, list[int]] = defaultdict(list)
            for src, dst in edges:
                successors_map[src].append(dst)

            out = []
            out.append("=" * 70)
            out.append(f"LOOP DETECTION: {func_name}")
            out.append("=" * 70)
            out.append(f"Function: {func_name} @ {func_addr}")
            out.append(f"Total loops detected: {len(loops)}")
            out.append("")

            if not loops:
                out.append("No natural loops detected in this function.")
                out.append("")
                out.append("This function appears to be loop-free (straight-line or")
                out.append("purely branching control flow).")
                return "\n".join(out)

            max_depth = max(nesting.values()) if nesting else 0
            out.append(f"Maximum nesting depth: {max_depth}")
            out.append("")

            for i, loop in enumerate(loops, 1):
                header = loop["header"]
                body = loop["body"]
                depth = nesting.get(header, 1)

                # Find exit edges: edges from body blocks to non-body blocks
                exit_points = []
                for blk_addr in body:
                    for succ in successors_map.get(blk_addr, []):
                        if succ not in body:
                            exit_points.append((blk_addr, succ))

                out.append(f"Loop {i}:")
                out.append(f"  Header:        0x{header:08x}")
                out.append(f"  Back edge:     0x{loop['back_edge_src']:08x} -> 0x{header:08x}")
                out.append(f"  Body blocks:   {len(body)}")
                out.append(f"  Nesting depth: {depth}")

                if exit_points:
                    out.append(f"  Exit edges ({len(exit_points)}):")
                    for src, dst in exit_points[:10]:
                        out.append(f"    0x{src:08x} -> 0x{dst:08x}")
                    if len(exit_points) > 10:
                        out.append(f"    ... and {len(exit_points) - 10} more")
                else:
                    out.append("  Exit edges:    none (infinite loop?)")

                out.append("  Body:")
                for addr in sorted(body):
                    marker = " [HEADER]" if addr == header else ""
                    out.append(f"    0x{addr:08x}{marker}")
                out.append("")

            return "\n".join(out)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("detect_loops", e)
        except Exception as e:
            logger.error(f"detect_loops failed: {e}")
            return safe_error_message("Failed to detect loops", e)

    # ------------------------------------------------------------------
    # Tool 3: find_dead_code
    # ------------------------------------------------------------------
    @app.tool()
    def find_dead_code(binary_path: str) -> str:
        """
        Find potentially dead or unreferenced code in the binary.

        Scans all functions in the cached analysis to identify:
        - Orphan functions: no callers and not the entry point
        - Functions never referenced by any other function

        Orphan functions may indicate hidden functionality, debug
        routines, or obfuscated code that is called indirectly.

        Args:
            binary_path: Path to an analyzed binary

        Returns:
            Report listing orphan functions and statistics

        Example:
            find_dead_code("/samples/malware.exe")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))
            context = _get_or_run_analysis(binary_path, cache, runner)
            functions = context.get("functions", [])
            metadata = context.get("metadata", {})

            if not functions:
                return "No functions found in the analysis. Run analyze_binary first."

            # Build a set of all function addresses and names
            func_addrs: dict[str, str] = {}  # normalized_addr -> name
            func_names: set[str] = set()
            for f in functions:
                addr = (f.get("address") or "").lower().replace("0x", "").lstrip("0") or "0"
                name = f.get("name", "")
                func_addrs[addr] = name
                func_names.add(name)

            # Build set of all called-function addresses/names
            called_addrs: set[str] = set()
            called_names: set[str] = set()
            for f in functions:
                for callee in f.get("called_functions", []):
                    addr = (callee.get("address") or "").lower().replace("0x", "").lstrip("0") or "0"
                    called_addrs.add(addr)
                    called_names.add(callee.get("name", ""))

            # Determine entry point from metadata
            entry_point = (
                str(metadata.get("min_address", "")).lower().replace("0x", "").lstrip("0") or "0"
            )

            # Find orphan functions
            orphans = []
            for f in functions:
                if f.get("is_external") or f.get("is_thunk"):
                    continue
                name = f.get("name", "")
                addr = (f.get("address") or "").lower().replace("0x", "").lstrip("0") or "0"

                # Skip entry point
                if addr == entry_point:
                    continue

                # Check if anyone calls this function
                is_called = addr in called_addrs or name in called_names
                if not is_called:
                    orphans.append(f)

            total_funcs = len([f for f in functions if not f.get("is_external") and not f.get("is_thunk")])

            out = []
            out.append("=" * 70)
            out.append("DEAD CODE ANALYSIS")
            out.append("=" * 70)
            out.append(f"Binary: {Path(binary_path).name}")
            out.append(f"Total internal functions: {total_funcs}")
            out.append(f"Orphan functions (no callers): {len(orphans)}")
            out.append("")

            if not orphans:
                out.append("No orphan functions detected.")
                out.append("All internal functions appear to be referenced.")
                return "\n".join(out)

            orphan_pct = (len(orphans) / total_funcs * 100) if total_funcs else 0
            out.append(f"Orphan percentage: {orphan_pct:.1f}%")
            out.append("")

            if orphan_pct > 30:
                out.append(
                    "NOTE: High orphan percentage may indicate indirect calls,")
                out.append(
                    "virtual dispatch tables, or callback-based architecture.")
                out.append("")

            # Sort by address
            orphans.sort(key=lambda f: f.get("address", ""))

            out.append(f"Orphan Functions ({len(orphans)}):")
            for i, f in enumerate(orphans):
                if i >= 100:
                    out.append(f"  ... and {len(orphans) - 100} more orphan functions")
                    break

                name = f.get("name", "unknown")
                addr = f.get("address", "?")
                num_blocks = len(f.get("basic_blocks", []))
                num_calls = len(f.get("called_functions", []))
                has_pseudo = bool(f.get("pseudocode"))

                out.append(f"  {name} @ {addr}")
                out.append(
                    f"    blocks={num_blocks}  calls={num_calls}  "
                    f"decompiled={'yes' if has_pseudo else 'no'}"
                )

            out.append("")
            out.append("These functions have no detected callers and may represent:")
            out.append("  - Hidden/obfuscated functionality (called via indirect jumps)")
            out.append("  - Callback functions (registered at runtime)")
            out.append("  - Dead code left from development")
            out.append("  - Export-only functions (DLLs)")

            return "\n".join(out)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("find_dead_code", e)
        except Exception as e:
            logger.error(f"find_dead_code failed: {e}")
            return safe_error_message("Failed to find dead code", e)

    # ------------------------------------------------------------------
    # Tool 4: get_function_complexity
    # ------------------------------------------------------------------
    @app.tool()
    def get_function_complexity(
        binary_path: str,
        function_name_or_address: str,
    ) -> str:
        """
        Compute comprehensive complexity metrics for a single function.

        Metrics include instruction count (estimated), basic block count,
        cyclomatic complexity, call count, parameter count, local variable
        count, loop count, and maximum nesting depth. Returns a scored
        complexity assessment.

        Args:
            binary_path: Path to an analyzed binary
            function_name_or_address: Function name or hex address

        Returns:
            Formatted complexity report with scored assessment

        Example:
            get_function_complexity("/samples/malware.exe", "main")
        """
        try:
            binary_path = str(sanitize_binary_path(binary_path))
            context = _get_or_run_analysis(binary_path, cache, runner)
            functions = context.get("functions", [])
            metadata = context.get("metadata", {})

            func = _find_function(functions, function_name_or_address)
            if not func:
                suggestions = _suggest_functions(functions, function_name_or_address)
                msg = f"Function '{function_name_or_address}' not found."
                if suggestions:
                    msg += f" Did you mean: {suggestions}?"
                return msg

            func_name = func.get("name", "unknown")
            func_addr = func.get("address", "?")
            basic_blocks = func.get("basic_blocks", [])
            called_funcs = func.get("called_functions", [])
            parameters = func.get("parameters", [])
            local_vars = func.get("local_variables", [])
            has_pseudo = bool(func.get("pseudocode"))

            num_blocks = len(basic_blocks)
            num_calls = len(called_funcs)
            num_params = len(parameters)
            num_locals = len(local_vars)

            # Estimate total instruction count from block sizes
            # Average x86 instruction is ~3-4 bytes; use 3.5 as estimate
            total_bytes = sum(bb.get("num_addresses", 0) for bb in basic_blocks)
            est_instructions = max(total_bytes // 4, num_blocks)

            # Try to build CFG for cyclomatic complexity and loop info
            cyclomatic = 1
            loop_count = 0
            max_nesting = 0
            cfg_available = False

            if num_blocks > 0:
                try:
                    from src.utils.binary_reader import BinaryReader

                    with BinaryReader(binary_path) as reader:
                        blocks, edges, entry_addr = _build_cfg(func, reader, metadata)
                    num_edges = len(edges)
                    cyclomatic = num_edges - len(blocks) + 2
                    loops = _find_loops(blocks, edges, entry_addr)
                    loop_count = len(loops)
                    nesting = _compute_nesting_depth(loops)
                    max_nesting = max(nesting.values()) if nesting else 0
                    cfg_available = True
                except Exception as e:
                    logger.debug(f"CFG build failed for complexity: {e}")
                    # Fallback: estimate cyclomatic from block count
                    cyclomatic = max(1, num_blocks)

            # Compute composite complexity score (0-100)
            score = 0
            score += min(cyclomatic * 3, 30)         # Up to 30 from cyclomatic
            score += min(num_blocks // 2, 20)         # Up to 20 from block count
            score += min(num_calls * 2, 15)           # Up to 15 from call count
            score += min(loop_count * 5, 15)          # Up to 15 from loops
            score += min(max_nesting * 5, 10)         # Up to 10 from nesting
            score += min(num_params * 2, 10)          # Up to 10 from params

            if score <= 15:
                level = "LOW"
                assessment = "Simple function with minimal branching."
            elif score <= 35:
                level = "MEDIUM"
                assessment = "Moderate complexity; manageable for manual analysis."
            elif score <= 60:
                level = "HIGH"
                assessment = "Complex function; consider breaking analysis into parts."
            else:
                level = "VERY HIGH"
                assessment = (
                    "Very complex function; likely contains heavy computation, "
                    "state machines, or obfuscated code."
                )

            out = []
            out.append("=" * 70)
            out.append(f"FUNCTION COMPLEXITY: {func_name}")
            out.append("=" * 70)
            out.append(f"Function: {func_name} @ {func_addr}")
            out.append("")

            out.append("Metrics:")
            out.append(f"  Basic blocks:          {num_blocks}")
            out.append(f"  Est. instructions:     ~{est_instructions}")
            out.append(f"  Total bytes:           {total_bytes}")
            out.append(f"  Cyclomatic complexity:  {cyclomatic}")
            out.append(f"  Function calls:        {num_calls}")
            out.append(f"  Parameters:            {num_params}")
            out.append(f"  Local variables:       {num_locals}")
            out.append(f"  Loops:                 {loop_count}")
            out.append(f"  Max nesting depth:     {max_nesting}")
            out.append(f"  Decompiled:            {'yes' if has_pseudo else 'no'}")
            if not cfg_available and num_blocks > 0:
                out.append("  (CFG unavailable - metrics are estimated)")
            out.append("")

            out.append(f"Complexity Score: {score}/100  [{level}]")
            out.append(f"Assessment: {assessment}")
            out.append("")

            # Breakdown
            out.append("Score Breakdown:")
            out.append(f"  Cyclomatic complexity:  {min(cyclomatic * 3, 30)}/30")
            out.append(f"  Block count:           {min(num_blocks // 2, 20)}/20")
            out.append(f"  Call count:            {min(num_calls * 2, 15)}/15")
            out.append(f"  Loop count:            {min(loop_count * 5, 15)}/15")
            out.append(f"  Nesting depth:         {min(max_nesting * 5, 10)}/10")
            out.append(f"  Parameter count:       {min(num_params * 2, 10)}/10")
            out.append("")

            # Called functions
            if called_funcs:
                out.append(f"Called Functions ({num_calls}):")
                for callee in called_funcs[:20]:
                    c_name = callee.get("name", "unknown")
                    c_addr = callee.get("address", "?")
                    out.append(f"  {c_name} @ {c_addr}")
                if num_calls > 20:
                    out.append(f"  ... and {num_calls - 20} more")
                out.append("")

            return "\n".join(out)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("get_function_complexity", e)
        except Exception as e:
            logger.error(f"get_function_complexity failed: {e}")
            return safe_error_message("Failed to compute complexity", e)

    logger.info("Registered 4 control flow analysis tools")
