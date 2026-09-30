"""
Flag known decompiler artifacts in Ghidra pseudocode before a model reads it.

Ghidra emits some constructs that look like ordinary C but are not what the
binary does, and a downstream reader has no signal to distrust them:

- ``unaff_RBX`` -- a register the decompiler couldn't attribute to anything
  in this function. ``return unaff_RBX;`` is not a real return value.
- ``extraout_RAX`` -- a register value left over from a call whose prototype
  says it doesn't produce one. Usually means that callee's prototype is wrong.
- ``in_RAX`` / ``in_stack_00000028`` -- an input the signature doesn't
  declare, so the parameter list is incomplete.
- Calls to variadic APIs (``wsprintfW``, ``DbgPrintEx``...) whose argument
  lists Ghidra frequently truncates to the prototype's fixed arity.
- Compiler/CFG helpers (``_guard_dispatch_icall``, ``__security_check_cookie``)
  that read as if they were the program's own dispatch or check logic.
- Ghidra's own ``/* WARNING: ... */`` comments (unrecovered jump tables,
  bad instruction data, non-returning calls).

This module only reads pseudocode; it never changes the cache. Renderers call
``annotate`` to get a copy with inline markers plus a summary block, so a
line like ``return unaff_RBX;`` arrives with the warning attached to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Inline markers are C comments so the body still reads as code.
MARKER_PREFIX = "/* [caveat] "
# A marker this module appended: at end of line, and closed. Sample text can
# contain the prefix, but not in this position -- and re-annotating replaces
# it rather than trusting it.
_EXISTING_MARKER_RE = re.compile(r"\s*" + re.escape(MARKER_PREFIX) + r".*\*/\s*$")

_UNAFF_RE = re.compile(r"\bunaff_\w+")
_EXTRAOUT_RE = re.compile(r"\bextraout_\w+")
# Ghidra's unmodelled-input names use the register/storage name in capitals
# (in_RAX, in_FS_OFFSET, in_XMM0_Qa) or in_stack_<hex>. A lower-case suffix
# is a user variable like ``in_buffer`` and is left alone.
_IN_RE = re.compile(r"\bin_(?:stack_[0-9a-fA-F]+|[A-Z][A-Z0-9]*(?:_[A-Za-z0-9]+)*)\b")
_RETURN_RE = re.compile(r"^\s*return\b")
_WARNING_RE = re.compile(r"/\*\s*WARNING:\s*(.*?)\s*\*/")
_HALT_RE = re.compile(r"\bhalt_baddata\s*\(")

# Standard C / Win32 / NT variadic formatting functions. Matched with an
# optional import/thunk prefix so ``__imp_wsprintfW`` and ``thunk_DbgPrint``
# count too. va_list variants (vsprintf, _vsnwprintf...) are fixed-arity and
# deliberately absent.
VARIADIC_FUNCTIONS = frozenset({
    "printf", "wprintf", "fprintf", "fwprintf", "sprintf", "swprintf",
    "snprintf", "_snprintf", "_snwprintf", "sprintf_s", "swprintf_s",
    "_snprintf_s", "_snwprintf_s", "scanf", "sscanf", "swscanf", "fscanf",
    "sscanf_s", "swscanf_s",
    "wsprintfA", "wsprintfW", "wnsprintfA", "wnsprintfW",
    "StringCchPrintfA", "StringCchPrintfW", "StringCbPrintfA", "StringCbPrintfW",
    "StringCchPrintfExA", "StringCchPrintfExW", "StringCbPrintfExA", "StringCbPrintfExW",
    "RtlStringCchPrintfA", "RtlStringCchPrintfW", "RtlStringCbPrintfA", "RtlStringCbPrintfW",
    "RtlStringCchPrintfExW", "RtlStringCbPrintfExW",
    "DbgPrint", "DbgPrintEx", "KdPrint", "KdPrintEx",
    "_cprintf", "_cwprintf", "_scprintf", "_scwprintf",
})
_VARIADIC_RE = re.compile(
    r"\b(?:__imp_|thunk_|_imp__)?(" + "|".join(sorted(VARIADIC_FUNCTIONS, key=len, reverse=True)) + r")\s*\("
)

# Compiler-inserted helpers, with what they actually are. Keys are matched as
# whole identifiers anywhere in a line (calls and function-pointer reads).
COMPILER_HELPERS: dict[str, str] = {
    "_guard_dispatch_icall": "Control Flow Guard indirect-call dispatch: the real target is the function pointer loaded just before (usually into RAX); this is not a custom dispatcher",
    "__guard_dispatch_icall_fptr": "Control Flow Guard indirect-call dispatch pointer: the real target is the function pointer loaded just before; this is not a custom dispatcher",
    "_guard_check_icall": "Control Flow Guard target check before an indirect call; not program logic",
    "__guard_check_icall_fptr": "Control Flow Guard target check before an indirect call; not program logic",
    "_guard_xfg_dispatch_icall": "eXtended Flow Guard indirect-call dispatch; the real target is the function pointer loaded just before",
    "__guard_xfg_dispatch_icall_fptr": "eXtended Flow Guard indirect-call dispatch; the real target is the function pointer loaded just before",
    "_guard_xfg_check_icall": "eXtended Flow Guard target check; not program logic",
    "__guard_xfg_check_icall_fptr": "eXtended Flow Guard target check; not program logic",
    "guard_dispatch_icall_nop": "Control Flow Guard dispatch stub (CFG disabled); behaves as a plain indirect call",
    "__security_check_cookie": "/GS stack-cookie check inserted by the compiler; not an application integrity check",
    "__security_init_cookie": "/GS stack-cookie initialisation inserted by the compiler",
    "__GSHandlerCheck": "/GS exception-handler cookie check inserted by the compiler",
    "__report_gsfailure": "/GS failure path inserted by the compiler (fast-fails the process)",
    "__report_rangecheckfailure": "compiler-inserted bounds-check failure path",
    "__chkstk": "compiler stack probe for a large frame; not an allocation the program asked for",
    "_alloca_probe": "compiler stack probe for a large frame; not an allocation the program asked for",
    "__C_specific_handler": "SEH dispatcher from the C runtime; the handler logic lives in the scope table",
    "_RTC_CheckEsp": "debug-build runtime check (/RTC) inserted by the compiler",
    "__CxxFrameHandler3": "C++ EH frame handler from the runtime",
    "__CxxFrameHandler4": "C++ EH frame handler from the runtime",
}
_HELPER_RE = re.compile(r"\b(" + "|".join(sorted(map(re.escape, COMPILER_HELPERS), key=len, reverse=True)) + r")\b")

# Meanings for the Ghidra warnings that most often mislead a reader.
_WARNING_MEANINGS: tuple[tuple[str, str], ...] = (
    ("Could not recover jumptable", "switch targets were not recovered, so some case bodies are missing from this listing"),
    ("Control flow encountered bad instruction data", "decoding hit invalid bytes; the listing past that point is unreliable"),
    ("Removing unreachable block", "Ghidra dropped a block it thinks is unreachable; indirect jumps can make that wrong"),
    ("Subroutine does not return", "a callee is treated as non-returning, so code after the call is cut"),
    ("Type propagation algorithm not settling", "variable types may be inconsistent"),
    ("Unknown calling convention", "argument and return mapping is a guess"),
    ("Could not reconcile some variable overlaps", "some variables overlap in storage; values may be merged or split wrongly"),
    ("Instruction at", "overlapping or data-as-code instructions; the listing may be wrong near this address"),
)


@dataclass(frozen=True)
class Caveat:
    kind: str
    detail: str
    line: int  # 1-based line in the pseudocode, 0 when not line-specific
    meaning: str

    def summary(self) -> str:
        where = f" (line {self.line})" if self.line else ""
        return f"{self.kind}: `{self.detail}`{where} -- {self.meaning}"


def _warning_meaning(text: str) -> str:
    for needle, meaning in _WARNING_MEANINGS:
        if needle in text:
            return meaning
    return "Ghidra flagged this function; treat the listing as approximate"


def find_caveats(pseudocode: str) -> list[Caveat]:
    """Return every known artifact in ``pseudocode``, one per (kind, detail).

    The first occurrence's line is kept; later repeats of the same name add
    nothing a reader needs.
    """
    return _scan(pseudocode)[0]


def _scan(
    pseudocode: str,
) -> tuple[list[Caveat], dict[int, dict[tuple[str, str], Caveat]]]:
    """One pass, two views: the deduped list and the per-line grouping.

    ``annotate`` needs both. Deriving the second by re-running the whole
    regex battery per line -- which is what it used to do -- costs a second
    ~7 scans of every line of a body that can run to 10K lines, on the
    decompile path, for information this pass already has in hand.
    """
    if not pseudocode:
        return [], {}
    found: dict[tuple[str, str], Caveat] = {}
    per_line: dict[int, dict[tuple[str, str], Caveat]] = {}

    def add(kind: str, detail: str, line: int, meaning: str) -> None:
        caveat = Caveat(kind, detail, line, meaning)
        found.setdefault((kind, detail), caveat)
        # Keyed per line, so a repeat on a later line still marks that line
        # even though the deduped list keeps only the first occurrence.
        per_line.setdefault(line, {}).setdefault((kind, detail), caveat)

    for lineno, line in enumerate(pseudocode.splitlines(), 1):
        for m in _WARNING_RE.finditer(line):
            add("decompiler-warning", m.group(1), lineno, _warning_meaning(m.group(1)))
        if _HALT_RE.search(line):
            add("bad-instruction", "halt_baddata()", lineno,
                "Ghidra could not decode the bytes here; code past this point is not real")
        code = _WARNING_RE.sub("", line)
        is_return = bool(_RETURN_RE.match(code))
        for m in _UNAFF_RE.finditer(code):
            if is_return:
                add("unaffected-return", m.group(0), lineno,
                    "returns a register value the decompiler could not attribute; this is not a real return value")
            else:
                add("unaffected-register", m.group(0), lineno,
                    "register value the decompiler could not attribute (often a callee-saved register or an unmodelled input); don't treat it as program data")
        for m in _EXTRAOUT_RE.finditer(code):
            add("extraout-register", m.group(0), lineno,
                "value left in a register by a call whose prototype says it returns nothing there; the callee's prototype is probably wrong")
        for m in _IN_RE.finditer(code):
            add("undeclared-input", m.group(0), lineno,
                "input read from a register or stack slot the signature doesn't declare; the parameter list is incomplete")
        for m in _VARIADIC_RE.finditer(code):
            add("variadic-call", m.group(1), lineno,
                "variadic callee; Ghidra often truncates the argument list to the fixed parameters, so don't draw argument-count conclusions without the disassembly")
        for m in _HELPER_RE.finditer(code):
            add("compiler-helper", m.group(1), lineno, COMPILER_HELPERS[m.group(1)])
    return list(found.values()), per_line


def _inline_note(kinds_on_line: dict[str, Caveat]) -> str | None:
    """Short marker for a single line, or None when nothing on it warrants one."""
    notes = []
    for c in kinds_on_line.values():
        if c.kind == "unaffected-return":
            notes.append(f"{c.detail} is a decompiler artifact, not a real return value")
        elif c.kind == "extraout-register":
            notes.append(f"{c.detail} is an artifact of a wrong callee prototype")
        elif c.kind == "variadic-call":
            notes.append(f"{c.detail} is variadic; argument list may be truncated")
        elif c.kind == "compiler-helper":
            notes.append(f"{c.detail} is compiler-inserted, not program logic")
        elif c.kind == "bad-instruction":
            notes.append("undecodable bytes; listing unreliable from here")
    return "; ".join(notes) or None


def annotate(pseudocode: str, max_summary: int = 12) -> tuple[str, list[str]]:
    """Return ``(annotated_pseudocode, summary_lines)``.

    Lines that carry a high-signal artifact (an ``unaff_`` return, an
    ``extraout_`` value, a variadic call, a compiler helper, bad data) get a
    trailing ``/* [caveat] ... */`` comment. ``summary_lines`` is a short
    markdown block for under the code, empty when there is nothing to say.
    """
    caveats, per_line = _scan(pseudocode)
    if not caveats:
        return pseudocode, []

    # Mark every line an artifact appears on, not only its first occurrence:
    # the reader meets each line in place.
    lines = pseudocode.splitlines()
    for idx, line in enumerate(lines):
        # Strip a marker this function appended on an earlier pass rather
        # than skipping the line. Skipping on `MARKER_PREFIX in line` let the
        # SAMPLE suppress its own warning: Ghidra reproduces the binary's
        # string constants and symbol names, so a sample carrying the literal
        # "/* [caveat] " anywhere on a line silenced the inline note for it
        # while the summary below still counted it -- the two disagreed and
        # the reader had no way to tell which was right.
        base = _EXISTING_MARKER_RE.sub("", line)
        note = _inline_note(per_line.get(idx + 1, {}))
        lines[idx] = f"{base}  {MARKER_PREFIX}{note} */" if note else base
    annotated = "\n".join(lines)
    if pseudocode.endswith("\n"):
        annotated += "\n"

    summary = [
        f"**Decompiler caveats ({len(caveats)})** -- known artifacts; verify against disassembly before relying on them:"
    ]
    for c in caveats[:max_summary]:
        summary.append(f"- {c.summary()}")
    if len(caveats) > max_summary:
        summary.append(f"- ... and {len(caveats) - max_summary} more")
    return annotated, summary


def render_c_block(pseudocode: str, fence: bool = True) -> list[str]:
    """Annotated pseudocode as output lines, followed by its caveat summary.

    The shared renderer for every tool that hands pseudocode to a caller, so
    they all flag the same artifacts the same way.
    """
    annotated, summary = annotate(pseudocode)
    out = ["```c", annotated, "```"] if fence else [annotated]
    if summary:
        out.append("")
        out.extend(summary)
    return out
