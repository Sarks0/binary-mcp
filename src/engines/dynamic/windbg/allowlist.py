"""
Fail-closed ALLOWLIST validator for every command the WinDbg bridge issues.

Second remediation pass. The previous implementation of this module was a
DENYLIST that named dangerous commands (``.shell``, ``.dvalloc``, ``eb`` ...)
and let everything else through. That is architecturally unsound for the
WinDbg command language and the adversarial review proved it by execution:

  * WinDbg has *command-string carriers* -- commands whose ARGUMENT is itself
    a command, executed later (``bp``/``bu``/``bm``/``ba``/``bs``/``bsc``
    breakpoint command lists, ``~*e``/``~0 e`` thread commands where
    "CommandString includes the rest of the input line", ``sxe -c``/``-c2``,
    ``.pcmd -s``, ``.idle_cmd``, ``.ocommand`` (which lets the DEBUGGEE inject
    commands), ``.browse``, ``!list -x``, the ``!for_each_*`` family, and the
    trailing ``Command`` argument of ``p``/``t``/``pa``/``pc``/``ph``/``pt``/
    ``ta``/``tb``/``tc``/``th``/``tt``/``wt``/``g``). Every one of those was a
    straight bypass of a first-token denylist.
  * Nearly every denied command has an undenied TWIN: ``.readmem`` for
    ``.writemem``, ``.logappend`` / ``.write_cmd_hist`` for ``.logopen``,
    ``.server`` for ``.remote``, ``q``/``qq``/``qd`` for ``.kill``/``.detach``,
    ``.settings set Symbols.Sympath`` for ``.sympath``, plus ``.send_file``,
    ``.copysym``, ``.dumpcab``, ``.kdfiles``, ``.setdll``, ``.extpath``,
    ``.scriptdebug``, ``.nvload``, ``.dbgdbg``, ``.netuse``, ``.createdir``,
    ``.exdicmd``.
  * Write/exec primitives kept being discovered one at a time: ``wrmsr``
    (write LSTAR -> syscall hook), ``ob``/``ow``/``od`` (I/O ports),
    ``!eb``/``!ed`` (physical memory), ``!ecb``/``!ecd``/``!ecw`` (PCI config),
    ``f``/``fp``, ``m``, ``.fiximports``, ``.closehandle``,
    ``.allow_exec_cmds``, ``.apply_dbp``, ``g =Address``, ``.thread``,
    ``.trap``, ``.cxr /w``.
  * A bang token naming a DLL path -- ``!c:\\tmp\\evil.dll.anyexport`` -- makes
    dbgeng call LoadLibrary on that path INSIDE THE DEBUGGER PROCESS. No
    ``.load`` needed. So does the documented ``!DLLName.load`` alias.

Enumerating that surface is not a losing game so much as an unwinnable one:
the debugger's command set is open (extensions add verbs at runtime) while a
denylist is closed. This module therefore inverts the decision: a subcommand
runs only if its command name appears in a curated read-only/inspection
allowlist, and anything unrecognised is refused. New WinDbg verbs, new
extension exports and misspellings all fail CLOSED.

Layering (see also ``windbg_tools.windbg_execute_command``): THIS MODULE IS
THE AUTHORITATIVE GATE. It is applied by ``WinDbgBridge._validate_command_safety``
on every command that reaches the engine, whether the caller is one of the 32
structured tools or the raw ``windbg_execute_command`` tool. The tool layer no
longer runs a second, differently-shaped substring scan; it only decides
whether the raw command tool is exposed at all.

Contents of the allowlist were derived from what this project actually issues
(``bl``, ``bc``, ``r``, ``u ... L<n>``, ``lm``/``lm k``, ``kn``, ``~<n>s``,
``dt -r<n>``, ``ba <kind> <size> <addr>``, ``.break``, ``!process 0 0``,
``!thread``, ``!drvobj``, ``!devobj``, ``!pool``, ``!object``, ``!analyze -v``
and the conditional-breakpoint string ``bp <addr> ".if (<cond>) {} .else
{gc}"``) plus the read-only inspection commands an analyst needs.

Validation passes:

  1. :func:`parse_compound` splits on every separator WinDbg honours -- ``;``
     and raw newlines -- outside quoted regions and ``{...}`` blocks.
  2. :func:`validate_command` checks each subcommand: bang-token path form,
     argument-form deny rules, the allowlist itself, an "arguments forbidden"
     rule for commands whose argument is a redirect or a payload, and then
     recursion into the quoted/braced command-string arguments of the few
     carriers that are allowed at all. Recursion is depth-capped.

Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
"""

from __future__ import annotations

import re

# Maximum nesting level validate_command will recurse through. Real analysis
# commands nest one or two levels (a .foreach body, a .if body inside it); the
# only thing that reaches double digits is a payload built to exhaust the
# interpreter stack. Rejecting past the cap is both safe (deny, never allow)
# and cheap.
_MAX_VALIDATION_DEPTH = 8

_MAX_COMMAND_LEN = 4096
_MAX_SUBCOMMANDS = 16

# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------
#
# Matched case-insensitively against the first whitespace-delimited token of
# each subcommand, sigils included ("shell" is harmless, ".shell" is not).
#
# Everything here is a display/inspection command, an execution-control command
# in its argument-free form, or one of the six breakpoint verbs the structured
# tools need. Anything NOT here is refused -- that is the whole point of the
# rewrite, so resist the urge to add a verb without checking the current
# debugger docs for a write, file, network, module-load or command-string
# argument on it.
_ALLOWED_EXACT = frozenset({
    # -- Memory / data display. The whole "d*" family reads; none of it
    #    writes (the write family is "e*", which is absent).
    "d", "da", "db", "dc", "dd", "df", "dg", "dl", "dp", "dq", "ds", "du",
    "dw", "dyb", "dyd",
    "dda", "ddp", "ddu", "dds",
    "dpa", "dpp", "dpu", "dps",
    "dqa", "dqp", "dqu", "dqs",
    # Typed structure dump + local variables. "dt -r<n> nt!_EPROCESS <addr>"
    # is what windbg_dt issues.
    "dt", "dv",
    # NOTE the deliberate absence of "dx". The debugger object model exposes
    # Debugger.Utility.Control.ExecuteCommand() and Debugger.Utility.FileSystem
    # to dx expressions, which makes dx a command-string carrier and a host
    # file-I/O primitive wearing a display command's clothes.
    #
    # -- Disassembly. "u <addr> L<count>" is what windbg_disassemble issues.
    "u", "ub", "uf", "up",
    # -- Symbols and modules. "lm" / "lm k" back get_loaded_drivers().
    "x", "ln", "lm", "!lmi", "!dh",
    # -- Registers. Read form only: the "=" argument form is refused below.
    "r",
    # -- Breakpoint management (no command-string argument).
    #    "bl" backs windbg_list_breakpoints, "bc <addr>" backs the
    #    delete_breakpoint fallback path.
    "bl", "bc", "bd", "be",
    # -- Breakpoint setters. These DO take a command string that runs when the
    #    breakpoint hits, so they are carriers: see _COMMAND_STRING_CARRIERS,
    #    which forces the quoted body back through this validator.
    "bp", "bu", "bm", "ba", "bs", "bsc",
    # -- Execution control. Argument-free forms only (_BARE_ONLY): "g =Address"
    #    redirects execution to an attacker-chosen address and "p"/"t" take a
    #    trailing command string.
    "g", "gc", "gu", "p", "t", ".break",
    # -- Control flow. Carriers: their braced bodies are re-validated.
    #    ".if"/".else" are required by the conditional-breakpoint string the
    #    windbg_set_conditional_breakpoint tool builds.
    ".if", ".else", ".elsif", ".foreach", ".for", ".while",
    # -- Session / target information, all read-only.
    "vertarget", "version", ".lastevent", ".exr", ".ecxr", ".cxr",
    ".frame", ".process", ".time", ".chain", ".formats", ".tlist",
    ".outmask", ".bugcheck", ".reload", ".echo", ".printf", ".help",
    "?", "??",
    # -- Kernel/user inspection extensions shipped with the debugger. Curated:
    #    read-only exports only. !chkimg is here in its comparison form; its
    #    -f "fix the image" form is refused below.
    "!analyze", "!process", "!thread", "!peb", "!teb", "!handle", "!object",
    "!drvobj", "!devobj", "!devstack", "!devnode", "!irp", "!irpfind",
    "!pool", "!poolused", "!poolfind", "!address", "!pte", "!vad", "!vm",
    "!memusage", "!filecache", "!ready", "!running", "!locks", "!session",
    "!token", "!sd", "!acl", "!apc", "!dpcs", "!idt", "!pcr", "!prcb",
    "!cpuinfo", "!sysinfo", "!stacks", "!numa", "!heap", "!gle", "!error",
    "!ustr", "!str", "!chkimg",
})

# Allowed command names that are families rather than fixed spellings. Matched
# (fullmatch) against the first token only, so arguments are still free-form.
_ALLOWED_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Stack traces: k, kb, kc, kd, kf, kk, kl, km, kn, kp, kv and the usual
    # combinations (knf, kvn ...). "kn 0x<frames>" is what get_stack issues.
    # None of the suffixes turn k into a write.
    re.compile(r"k[bcdfklmnpv]*"),
)

# Allowed forms matched against the WHOLE subcommand, because the argument is
# what makes them safe or unsafe.
_ALLOWED_WHOLE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Thread specifier. "~", "~*", "~.", "~#", "~<n>", optionally followed by
    # "s" (switch context -- "~<n>s" is what switch_thread/get_stack issue) or
    # a stack command ("~*k").
    #
    # This is matched against the ENTIRE subcommand on purpose. WinDbg's
    # thread-specific "e" form -- "~*e <cmd>" / "~0 e <cmd>" -- documents that
    # "CommandString includes the rest of the input line", i.e. the argument is
    # a command that this validator would never otherwise see. Requiring the
    # whole subcommand to be a bare specifier means any trailing text at all
    # (an "e", a command, anything) fails the match and is refused.
    re.compile(r"~(?:\*|\.|#|\d+)?(?:s|k[bcdfklmnpv]*)?"),
)

# Commands whose ENTIRE subcommand must be just the command name. Two reasons
# appear here:
#   - the argument form is an execution redirect or a payload: "g =Address"
#     resumes at an attacker-chosen address; "p"/"t" and the rest of the step
#     family take a trailing CommandString executed after the step.
#   - the documented syntax takes no parameters at all: current debugger docs
#     give ".bugcheck" with no arguments (it DISPLAYS the bug check data of a
#     crash dump). The previous denylist rule refused ".bugcheck <code>" as a
#     "bugcheck simulator", which is an undocumented syntax; requiring the bare
#     form is both correct and stricter.
_BARE_ONLY = frozenset({
    "g", "gc", "gu", "p", "t", ".break", ".bugcheck",
    "vertarget", "version", ".lastevent", ".ecxr", ".chain",
})

# Allowed commands that carry another command in their arguments. For these --
# and ONLY these -- validate_command recurses into every ``{...}`` block and
# every single- OR double-quoted body and validates it as a command in its own
# right. For every other allowed command the quoted text is data (".printf
# \"it's fine\"", ".echo hello world") and is left alone.
#
# Double-quoted recursion is the half the first remediation pass missed: it
# added single-quote recursion (for j/z) and left ``bp X ".shell calc"`` --
# the documented breakpoint command list, which runs on every hit -- entirely
# unvalidated.
# RESIDUAL RISK, stated rather than hidden: ``.foreach`` substitutes whitespace
# tokens taken from the OUTPUT of its in-list command into its body before
# executing it, and in kernel mode that output (process names, module names)
# is influenced by the debuggee. The body's first token must still be a literal
# allowlisted command -- substituted text can only land in argument position --
# but a substituted token containing ';' would be re-split by the debugger
# after this validator has run, and no static check upstream of the debugger
# can see that. ``.foreach`` is kept because bulk inspection is its whole
# purpose; prefer the structured tools when one exists.
_COMMAND_STRING_CARRIERS = frozenset({
    "bp", "bu", "bm", "ba", "bs", "bsc",
    ".if", ".else", ".elsif", ".foreach", ".for", ".while",
})

# A bang token that names a path, a drive or a dotted module. dbgeng resolves
# "!module.export" by calling LoadLibrary on `module` inside the DEBUGGER
# PROCESS, so "!c:\tmp\evil.dll.anyexport" is arbitrary code execution on the
# analyst host with no ".load" anywhere in the command; "!DLLName.load" is the
# documented alias for the same thing. The allowlist already refuses these
# (no entry contains a path character), but the check is explicit so the
# refusal names the reason and so a future allowlist addition containing a dot
# cannot quietly reopen it.
_BANG_MODULE_PATH_RE = re.compile(r"^!.*[\\/:.]")

# Argument-form deny rules, matched case-insensitively against the whole
# subcommand. These refine commands that ARE on the allowlist but have one
# unsafe argument shape. Evaluated before the allowlist so the refusal message
# names the specific primitive.
_DENY_ARGFORM: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        # '??' evaluates a C++ expression, and that evaluator supports
        # ASSIGNMENT -- '?? *(char*)0x401000 = 0x90' writes target memory. The
        # allowlist admits '??' as a read-only evaluator on the rationale that
        # the write family is e*, which this misses entirely. Allow comparisons
        # (==, !=, <=, >=) and reject a bare '=' anywhere in the expression.
        re.compile(r"^\s*\?\?.*(?<![=!<>])=(?!=)"),
        "'??' with an assignment is forbidden: the expression evaluator "
        "writes target memory. Use the read-only comparison forms",
    ),
    (
        # Script-file include operators: $<, $><, $$<, $$><, $$>a< all run an
        # arbitrary debugger command file from disk. Anchored at the subcommand
        # start so a legitimate pseudo-register use ("@$teb") is untouched.
        re.compile(r"^\s*\$\$?>?a?<", re.IGNORECASE),
        "script-file include ($<, $$<, $$>a< ...) is forbidden; "
        "it runs an arbitrary debugger command file",
    ),
    (
        # Register write. The old rule was r"^\s*r\s+[^\s,]+\s*=\s*\S", which
        # required whitespace after "r" and so missed BOTH documented no-space
        # forms: "r@rip=401000" and "rrax=401000". It also missed "r$.u0=...",
        # which defines an alias -- and WinDbg expands aliases BEFORE parsing,
        # so that one smuggles any command past every check in this module.
        # Under the allowlist those three are already refused (their first
        # token is not "r"), and this rule now refuses any "=" in an r command
        # rather than trying to describe the write syntax.
        re.compile(r"^\s*r\s+[^;]*=", re.IGNORECASE),
        "register write via 'r' is forbidden; use a structured tool",
    ),
    (
        re.compile(r"^\s*\.process\s+/i\b", re.IGNORECASE),
        ".process /i (invasive switch + resume) is forbidden",
    ),
    (
        # The old rule matched "/f". The DOCUMENTED switch for "fix the loaded
        # image" is "-f", so the rule never fired on the real syntax -- it was
        # inert. Both spellings are refused now.
        re.compile(r"^\s*!chkimg\b.*(?:^|\s)[-/]f(?:\s|$)", re.IGNORECASE),
        "!chkimg -f patches the loaded image; only the comparison form is allowed",
    ),
    (
        # .cxr sets the debugger's register context from a CONTEXT record. Its
        # switch forms (documented and undocumented, "/w" among them) go beyond
        # that, so the bare "address" form is the only one permitted.
        re.compile(r"^\s*\.cxr\b.*(?:^|\s)/", re.IGNORECASE),
        ".cxr switches are forbidden; only '.cxr [address]' is allowed",
    ),
    (
        re.compile(r"^\s*\.printf\b.*\s/D\b", re.IGNORECASE),
        ".printf /D (DML output) is forbidden; plain .printf is allowed",
    ),
)

# ---------------------------------------------------------------------------
# NOTE on rules deliberately NOT present any more
#
# "s -[bdwq]" was refused as a "search-and-write variant". There is no such
# thing: "s" is Search Memory, and -b/-w/-d/-q are the pattern TYPE specifiers
# for the bytes being searched FOR. The rule was a pure over-block with zero
# security benefit, so it is gone. Search itself is now refused by absence from
# the allowlist rather than by a false claim about a write form -- "s" is not
# issued anywhere in this project and its argument grammar (patterns, ranges,
# "-[su]" for string search) is large enough that permitting it would need its
# own analysis.
#
# ".writevirtmem" is likewise gone from every list and comment here: it is not
# a command in current WinDbg. Reasoning about it made the old module docstring
# describe a control over something that does not exist.
# ---------------------------------------------------------------------------


def parse_compound(command: str) -> list[str]:
    """Split a WinDbg command on ``;``/newline outside quotes and ``{...}``.

    WinDbg uses ``;`` and raw newlines as sequencers but they also appear
    inside quoted strings (``.printf "a;b"``) and inside ``.foreach`` bodies
    (``.foreach (x {!process 0 0}) {!handle ${x}}``). A naive ``split(";")``
    would either over-split (rejecting legitimate composite commands) or
    under-split (letting a command slip through a quoted argument), so this
    tokenizer tracks quote and brace depth and hands each subcommand to the
    validator independently.

    Two behaviours here are load-bearing and were wrong before:

    * There is NO backslash escape. The previous version treated ``\\<ch>`` as
      an escaped pair and copied it through, which invented an escape WinDbg
      does not implement and desynchronised this split from the debugger's:
      ``dt nt!_EPROCESS\\;.dvalloc 1000`` was one harmless ``dt`` subcommand
      here and two subcommands in cdb, the second allocating RWX memory in the
      target. Without the escape the split matches the debugger's, and any
      residual disagreement about ``\\"`` now errs towards splitting MORE
      (more subcommands validated), never fewer.
    * An unbalanced ``${`` no longer swallows the remainder of the line into
      the current part. It used to, which meant one stray ``${`` hid an entire
      payload behind a harmless leading token. The ``$`` is now an ordinary
      character in that case, and :func:`validate_command` refuses the command
      outright.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_dq = False
    in_sq = False
    i = 0

    def _leading_is_carrier() -> bool:
        """True if the part being built starts with a command-string carrier.

        Brace blocks and ``${...}`` interpolation are constructs of the carrier
        commands (``.foreach``, ``.for``, ``.if``, the breakpoint family). For
        every OTHER command a ``{`` is just an ordinary character to WinDbg.

        Suppressing ';' splitting inside braces unconditionally -- which is what
        this tokenizer used to do -- therefore created a blind spot precisely
        where nothing compensated for it: validate_command recurses into braces
        only for carriers, so for a non-carrier the brace content was neither
        split nor recursed into. ``lm {;.shell calc}``, ``k {;.shell calc}``,
        ``!analyze -v {;.shell calc}`` and ``r {;q}`` all reached the debugger
        behind a harmless leading token. Gating the suppression on the leading
        token closes that: for a non-carrier the braces stop being protective,
        the ';' splits as cdb would split it, and the payload is validated as
        its own subcommand.
        """
        return _first_token("".join(current)) in _COMMAND_STRING_CARRIERS

    while i < len(command):
        ch = command[i]
        # ${...} is variable interpolation in .foreach / .for, not a block --
        # and only inside those carriers, hence the same gate as braces below.
        if (
            not in_dq
            and not in_sq
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
            and _leading_is_carrier()
        ):
            j = command.find("}", i + 2)
            if j != -1:
                current.append(command[i:j + 1])
                i = j + 1
                continue
            # Unbalanced. Copy "${" through as literal text WITHOUT letting
            # the '{' raise the brace depth -- if it did, every subsequent ';'
            # and newline would look like it was inside a block and the whole
            # remainder of the line would end up in one part behind a harmless
            # leading token, which is exactly the bug being fixed.
            # validate_command refuses the command outright as well; this
            # keeps the tokenizer honest either way.
            current.append("${")
            i += 2
            continue
        if not in_sq and ch == '"':
            in_dq = not in_dq
            current.append(ch)
        elif not in_dq and ch == "'":
            in_sq = not in_sq
            current.append(ch)
        elif not in_dq and not in_sq and ch == "{" and (depth > 0 or _leading_is_carrier()):
            # depth > 0 keeps nested braces inside an already-open carrier block
            # balanced; the carrier test decides whether the OUTERMOST brace is
            # protective at all. See _leading_is_carrier for why.
            depth += 1
            current.append(ch)
        elif not in_dq and not in_sq and ch == "}" and depth > 0:
            depth = max(0, depth - 1)
            current.append(ch)
        elif not in_dq and not in_sq and depth == 0 and ch in ";\n\r":
            # WinDbg honours BOTH ';' and raw newlines as command separators.
            # Empty pieces (from '\r\n' or ';;') are dropped so a separator run
            # does not manufacture an "empty subcommand" rejection.
            piece = "".join(current).strip()
            if piece:
                parts.append(piece)
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _first_token(subcommand: str) -> str:
    """Return the lowered first whitespace-delimited token, with leading sigils."""
    s = subcommand.strip()
    if not s:
        return ""
    # Split on ASCII space/tab only, and case-fold ASCII only.
    #
    # Python's \S treats VT, FF, NEL (U+0085), NBSP and U+2028 as whitespace
    # while cdb does not, so 'lm\x0b.dvalloc 1000' presented to this validator
    # as a bare 'lm' with arguments and to the debugger as something else
    # entirely. And str.lower() performs UNICODE case folding, so U+212A
    # (KELVIN SIGN) lowered to 'k' and satisfied the k-family stack pattern.
    # _structural_problem now rejects non-ASCII and stray control characters
    # outright, so neither reaches here; these two narrowings make the
    # tokenizer correct on its own rather than relying on that alone.
    m = re.match(r"[^ \t]+", s)
    if not m:
        return ""
    token = m.group(0)
    return token.lower() if token.isascii() else token


def _structural_problem(command: str) -> str | None:
    """Return a reason string if the command is structurally malformed.

    Every protected region this validator honours -- ``${...}``
    interpolation, ``{...}`` blocks, ``'...'`` and ``"..."`` strings -- is a
    region where :func:`parse_compound` deliberately stops splitting on ``;``
    and newlines. An UNTERMINATED region therefore extends to the end of the
    input and hides everything after it inside one subcommand, behind whatever
    harmless token happens to lead. Three concrete versions of that:

      * ``k ${ ; .shell calc`` -- unbalanced interpolation swallowed the tail.
      * ``.foreach (a {!process 0 0}) {!handle ${a} ; .shell calc`` -- the
        block never closes, so the block extractor never sees ``.shell`` and
        the compound splitter never separates it.
      * ``lm "foo ; .shell calc`` -- the quote never closes, and ``lm`` is not
        a carrier so nothing recurses into the remainder.

    There is no way to know what cdb does with malformed input without being
    cdb, so the validator refuses it. Well-formed commands are unaffected, and
    the debugger would reject most of these itself.
    """
    # Character-set gate, checked before any structural parsing.
    #
    # WinDbg commands are ASCII. Anything else is either a homoglyph attack on
    # this validator or garbage cdb will not execute, and admitting it only
    # creates ways for the two tokenizers to disagree:
    #   * U+212A KELVIN SIGN lowercases to 'k' under Unicode case folding, so
    #     'Kb 401000' satisfied the k-family stack pattern here while cdb, which
    #     does not case-fold, saw a different command.
    #   * VT, FF, NEL (U+0085), NBSP and U+2028 are whitespace to Python's \S
    #     but not to cdb, so 'lm<VT>.dvalloc 1000' read as a bare 'lm' here.
    # Refusing both classes outright is fail-closed and costs nothing: no
    # legitimate debugger command needs them. Tab, newline and CR are exempt --
    # they are real separators this validator handles deliberately.
    for ch in command:
        if not ch.isascii():
            return (
                f"non-ASCII character {ch!r} (U+{ord(ch):04X}) in command; "
                "WinDbg commands are ASCII and look-alike characters are a "
                "known way to desynchronise validation from the debugger"
            )
        if ord(ch) < 0x20 and ch not in "\t\n\r":
            return (
                f"control character U+{ord(ch):04X} in command; it separates "
                "tokens for this validator but not for the debugger"
            )

    depth = 0
    in_dq = False
    in_sq = False
    i = 0
    while i < len(command):
        ch = command[i]
        if (
            not in_dq
            and not in_sq
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                return (
                    "unbalanced '${' alias interpolation; refusing rather "
                    "than guessing how the debugger splits the remainder"
                )
            i = j + 1
            continue
        if not in_sq and ch == '"':
            in_dq = not in_dq
        elif not in_dq and ch == "'":
            in_sq = not in_sq
        elif not in_dq and not in_sq:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth < 0:
                    return "unbalanced '}' block delimiter"
        i += 1
    if in_dq or in_sq:
        return (
            "unterminated quoted region; the rest of the line would be "
            "hidden from subcommand splitting"
        )
    if depth:
        return (
            "unterminated '{' block; the rest of the line would be hidden "
            "from subcommand splitting"
        )
    return None


def _is_allowed(first: str, part: str) -> bool:
    """True if ``first``/``part`` names a command on the allowlist."""
    if first in _ALLOWED_EXACT:
        return True
    for pattern in _ALLOWED_TOKEN_PATTERNS:
        if pattern.fullmatch(first):
            return True
    stripped = part.strip().lower()
    for pattern in _ALLOWED_WHOLE_PATTERNS:
        if pattern.fullmatch(stripped):
            return True
    return False


def validate_command(command: str, _depth: int = 0) -> tuple[bool, str | None]:
    """Validate a (possibly compound) WinDbg command string.

    Returns ``(True, None)`` if every subcommand is on the allowlist in an
    allowed argument form, else ``(False, reason)`` for the first violation.

    ``_depth`` is the internal nesting level: validation recurses into the
    ``{...}`` blocks and quoted command strings of the carriers, and a crafted
    command can nest those arbitrarily. The cap turns a would-be
    RecursionError into a clean rejection. Callers never pass it.
    """
    if _depth > _MAX_VALIDATION_DEPTH:
        return False, (
            f"command nesting too deep (max {_MAX_VALIDATION_DEPTH} levels)"
        )

    if not command or not command.strip():
        return False, "empty command"

    if len(command) > _MAX_COMMAND_LEN:
        return False, f"command too long (max {_MAX_COMMAND_LEN} chars)"

    problem = _structural_problem(command)
    if problem is not None:
        return False, problem

    parts = parse_compound(command)
    if not parts:
        return False, "empty command"

    # Bound compound depth to keep the validator deterministic.
    if len(parts) > _MAX_SUBCOMMANDS:
        return False, f"too many compound subcommands ({len(parts)} > {_MAX_SUBCOMMANDS})"

    for part in parts:
        first = _first_token(part)
        if not first:
            return False, "empty subcommand in compound"

        if _BANG_MODULE_PATH_RE.match(first):
            return False, (
                f"extension command {first!r} names a module path; dbgeng "
                "would LoadLibrary it into the debugger process"
            )

        for pattern, reason in _DENY_ARGFORM:
            if pattern.match(part):
                return False, reason

        if not _is_allowed(first, part):
            return False, (
                f"command {first!r} is denied: not in the read-only allowlist "
                f"(src/engines/dynamic/windbg/allowlist.py). Use a structured "
                f"windbg_* tool if one exists."
            )

        if first in _BARE_ONLY and part.strip().lower() != first:
            return False, (
                f"command {first!r} is only allowed in its bare form "
                f"(arguments to it are an execution redirect or a command "
                f"string)"
            )

        if first in _COMMAND_STRING_CARRIERS:
            # The argument of a carrier is another command -- a breakpoint
            # command list that runs on every hit, a .if/.foreach body, and so
            # on. It must satisfy exactly the same allowlist, so send it back
            # through the validator. Both ``{...}`` blocks and quoted bodies
            # count, and BOTH quote characters do: WinDbg's breakpoint command
            # lists are double-quoted, its j/z bodies single-quoted.
            inner = _extract_inner_block(part)
            if inner is not None:
                ok, why = validate_command(inner, _depth + 1)
                if not ok:
                    return False, f"in compound block: {why}"

            for body in _extract_quoted_bodies(part):
                ok, why = validate_command(body, _depth + 1)
                if not ok:
                    return False, f"in quoted subcommand: {why}"

    return True, None


def _extract_quoted_bodies(command: str) -> list[str]:
    """Return the bodies of the ``'...'`` and ``"..."`` regions in ``command``.

    Only called for :data:`_COMMAND_STRING_CARRIERS`, where a quoted region is
    a command string rather than data. The scanning rules are kept identical to
    :func:`parse_compound` so that what this hands back to the validator is
    exactly what that function treated as an opaque protected region:

      - the first quote character seen opens the region and only the matching
        character closes it, so ``"it's fine"`` is one body, not two;
      - ``${x}`` interpolation is skipped wholesale;
      - there is no backslash escape (see :func:`parse_compound`).

    An *unterminated* body is returned rather than dropped. That case is not
    merely sloppy input: parse_compound stops splitting on ``;`` once a quote
    opens, so ``bp X "foo ; .shell calc`` is a single subcommand whose first
    token is the harmless ``bp``. Validating the remainder keeps that path
    closed instead of failing open.
    """
    bodies: list[str] = []
    quote = ""
    start = -1
    i = 0
    while i < len(command):
        ch = command[i]
        if (
            not quote
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                break
            i = j + 1
            continue
        if ch in ("'", '"'):
            if not quote:
                quote = ch
                start = i + 1
            elif ch == quote:
                body = command[start:i]
                if body.strip():
                    bodies.append(body)
                quote = ""
                start = -1
        i += 1
    if quote and start >= 0:
        tail = command[start:]
        if tail.strip():
            bodies.append(tail)
    return bodies


def _extract_inner_block(command: str) -> str | None:
    """Pull the bodies out of ``.foreach (...) {body}`` / ``.if (...) {a} .else {b}``.

    Returns the concatenation of all top-level ``{...}`` block contents,
    separated by ``;``. None if no blocks are present.
    """
    blocks: list[str] = []
    depth = 0
    start = -1
    in_dq = False
    in_sq = False
    i = 0
    while i < len(command):
        ch = command[i]
        # Skip ${...} variable interpolation entirely.
        if (
            not in_dq
            and not in_sq
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                break
            i = j + 1
            continue
        if not in_sq and ch == '"':
            in_dq = not in_dq
        elif not in_dq and ch == "'":
            in_sq = not in_sq
        elif not in_dq and not in_sq:
            if ch == "{":
                if depth == 0:
                    start = i + 1
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
                if depth == 0 and start >= 0:
                    blocks.append(command[start:i])
                    start = -1
        i += 1
    if not blocks:
        return None
    return ";".join(b.strip() for b in blocks if b.strip())


__all__ = [
    "parse_compound",
    "validate_command",
]
