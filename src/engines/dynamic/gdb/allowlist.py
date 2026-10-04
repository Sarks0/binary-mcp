"""
Allowlist for GDB console commands reached through ``-interpreter-exec console``.

The MI surface is structured and safe: ``-break-insert``, ``-data-read-memory-bytes``
and friends do one thing each. The *console* surface is the whole of GDB's
command language, and it is hostile. Everything below was executed against GNU
gdb 15.1 in this repository, with a file on disk as the proof of execution:

===========================================  =======================================
input                                        result
===========================================  =======================================
``shell touch FILE``                         file created
``!touch FILE``                              file created (``!`` aliases ``shell``)
``python open('FILE','w')``                  file created
``print $_shell("touch FILE")``              **file created** -- see below
``pipe show version | head -1 > FILE``       file written with GDB's own output
``x/1x $_shell("touch FILE")``               **file created**, then the read failed
``eval "print %d", 1+1``                     command constructed and run
===========================================  =======================================

The two starred rows are why this module is an allowlist of *command names and
argument shapes* rather than a list of dangerous commands. ``$_shell`` is a
convenience function, so the escape lives in the **expression grammar**, not in
the command name: any command that evaluates an expression can reach a shell,
whichever name it is spelled with. Blocking ``shell`` and ``python`` while
allowing ``print`` or ``x`` would be security theatre.

Two structural findings, also measured, which make this simpler than the WinDbg
validator:

- ``;`` is **not** a command separator. ``show version ; shell touch FILE`` ran
  nothing. Neither is an embedded newline inside one MI console string. One
  console command is therefore one GDB command, and there is no compound
  splitting to get wrong.
- ``|`` is **not** a shell pipe outside the ``pipe`` command.
  ``info sharedlibrary | touch FILE`` ran nothing.

The direction of the gate follows this repository's x64dbg bridge, for the
reason argued there: a missing entry on a denylist is a missed block, while a
missing entry on an allowlist is only a missing feature. GDB sharpens that
argument further, because it resolves unique command *prefixes* -- ``she``
reaches ``shell`` -- so a denylist would have to name every abbreviation of
every dangerous command. An allowlist of exact names rejects abbreviations by
default, which costs a little convenience and closes the whole class.

What is deliberately **not** here, and why nothing is lost by it: the commands
an analyst actually needs for memory, registers, breakpoints, stepping and
disassembly all exist as MI commands, which the bridge issues directly without
touching this validator. The console is only needed for the informational
commands MI never grew -- ``info proc mappings``, ``info sharedlibrary`` -- so
the allowlist covers those and nothing that evaluates a user expression.
"""

from __future__ import annotations

import re

# A console command long enough to be interesting is almost certainly an
# attempt at something. Informational commands are short.
MAX_COMMAND_LENGTH = 300

# ``info`` is the useful half of the console surface, but not all of it is
# inert: ``info symbol``, ``info address`` and ``info line`` take expressions
# or linespecs that GDB evaluates. Only subcommands that take no expression --
# or take a plain identifier -- are listed.
_ALLOWED_INFO_SUBCOMMANDS = frozenset({
    # Process and address space. The reason the console is needed at all:
    # these have no MI equivalent, and info proc mappings is how a PIE
    # module's runtime load base is recovered.
    "proc",
    "sharedlibrary",
    "files",
    "target",
    "program",
    # Threads, frames and breakpoints: MI covers these, but the console forms
    # are read-only and the text is easier for a human reading a transcript.
    "threads",
    "frame",
    "breakpoints",
    "watchpoints",
    "registers",
    "all-registers",
    "stack",
    "args",
    "locals",
    # Symbols and sections, for orienting in a stripped or static binary.
    "functions",
    "variables",
    "types",
    "sources",
    "source",
    "scope",
    # Settings and environment, all inert.
    "signals",
    "handle",
    "auto-load",
    "inferiors",
    "display",
    "terminal",
    "architecture",
})

# ``maint`` is GDB's maintenance surface. It is not an attack surface in the
# ``shell`` sense, but it is large, undocumented, version-specific and can
# crash or reconfigure the debugger. Nothing in it is needed here.
#
# Anything not named in _ALLOWED_COMMANDS is refused, so this module contains
# no list of dangerous commands: shell, !, python, pi, py, guile, gu, source,
# define, document, alias, commands, eval, pipe, with, thread apply,
# frame apply, taas, faas, compile, make, edit, dump, append, restore,
# set, add-auto-load-safe-path, jump, return, call, print, p, output, printf,
# x, attach, detach, kill, run, start, target and every abbreviation of each
# are all rejected by omission rather than by enumeration.
_NO_ARGUMENTS = re.compile(r"^$")
_OPTIONAL_COUNT = re.compile(r"^(full|-full|\d{1,4})?$")
_OPTIONAL_FRAME = re.compile(r"^\d{0,4}$")
_SETTING_NAME = re.compile(r"^[a-z][a-z0-9-]{0,40}(\s+[a-z][a-z0-9-]{0,40}){0,2}$")
_LIST_SPEC = re.compile(r"^(\d{1,7}(,\d{1,7})?)?$")

# command name -> pattern the argument text (everything after the name) must
# match. Every pattern is anchored and bounded; none admits an expression.
_ALLOWED_COMMANDS: dict[str, re.Pattern[str]] = {
    # Stack inspection. "full" prints locals, still read-only.
    "backtrace": _OPTIONAL_COUNT,
    "bt": _OPTIONAL_COUNT,
    "where": _OPTIONAL_COUNT,
    # Frame and thread selection by index only -- "frame function foo" and
    # "frame address $sp" take expressions and are not admitted.
    "frame": _OPTIONAL_FRAME,
    "thread": _OPTIONAL_FRAME,
    # Settings readback. show takes a setting name, never an expression, and
    # the session layer relies on it to verify its own hardening.
    "show": _SETTING_NAME,
    # Source listing by line number.
    "list": _LIST_SPEC,
    # Version and configuration banners, for recording what was used.
    "version": _NO_ARGUMENTS,
}

# Reached only if an allowed command's argument pattern ever widens enough to
# admit one of these. Kept as a second, independent check because the first
# one is a human-maintained list of patterns and this one is a property of the
# escape itself: a convenience-function call is "$_" followed by a name and an
# open paren. $_shell is the one that executes today; matching the shape
# rather than the name means a future addition is refused before anyone here
# has heard of it.
_CONVENIENCE_CALL = re.compile(r"\$_\w*\s*\(")

# Characters with no place in an informational command's arguments. None of
# these is a GDB separator (measured), so each is blocked as defence in depth
# rather than because a bypass is known.
_FORBIDDEN_CHARS = {
    "|": "pipes GDB output into a shell command",
    ";": "command separator in other debuggers",
    "`": "shell command substitution",
    "\n": "embedded newline",
    "\r": "embedded carriage return",
    "\x00": "embedded NUL",
    ">": "output redirection",
    "<": "input redirection",
    "&": "shell backgrounding",
    "$(": "shell command substitution",
}


def allowed_commands() -> frozenset[str]:
    """Every console command name this validator accepts."""
    return frozenset(_ALLOWED_COMMANDS)


def allowed_info_subcommands() -> frozenset[str]:
    """Every ``info`` subcommand this validator accepts."""
    return frozenset(_ALLOWED_INFO_SUBCOMMANDS)


def validate_console_command(command: str) -> tuple[bool, str | None]:
    """Decide whether *command* may be sent to ``-interpreter-exec console``.

    Args:
        command: A single GDB console command, without the MI wrapper.

    Returns:
        ``(True, None)`` when the command is on the allowlist in an accepted
        argument form, otherwise ``(False, reason)``. The reason is written in
        this repository and names only the caller's own input, so it is safe to
        show to the model -- it never quotes host state.
    """
    if not command or not command.strip():
        return False, "empty command"

    if len(command) > MAX_COMMAND_LENGTH:
        return False, (
            f"command too long ({len(command)} chars, max {MAX_COMMAND_LENGTH})"
        )

    for needle, why in _FORBIDDEN_CHARS.items():
        if needle in command:
            return False, f"command contains {needle!r} ({why})"

    if _CONVENIENCE_CALL.search(command):
        return False, (
            "command calls a GDB convenience function; $_shell() runs a shell "
            "command, so convenience-function calls are refused wherever they "
            "appear"
        )

    stripped = command.strip()
    name, _, argument = stripped.partition(" ")
    name = name.strip()
    argument = argument.strip()

    if name == "info":
        return _validate_info(argument)

    rule = _ALLOWED_COMMANDS.get(name)
    if rule is None:
        return False, (
            f"console command {name!r} is not on the allowlist. Only "
            "read-only informational commands are permitted; use the "
            "structured MI tools for execution, memory and breakpoints"
        )

    if not rule.match(argument):
        return False, (
            f"console command {name!r} does not accept the argument "
            f"{argument!r} in this form"
        )

    return True, None


def _validate_info(argument: str) -> tuple[bool, str | None]:
    """Validate ``info <subcommand> [...]``."""
    if not argument:
        return False, (
            "bare 'info' lists every subcommand; name one of: "
            + ", ".join(sorted(_ALLOWED_INFO_SUBCOMMANDS))
        )

    subcommand, _, rest = argument.partition(" ")
    subcommand = subcommand.strip()
    rest = rest.strip()

    if subcommand not in _ALLOWED_INFO_SUBCOMMANDS:
        return False, (
            f"'info {subcommand}' is not on the allowlist. Permitted: "
            + ", ".join(sorted(_ALLOWED_INFO_SUBCOMMANDS))
        )

    # Remaining words must look like plain identifiers: "info proc mappings",
    # "info functions target". A regex or an expression is refused, because
    # "info functions" takes a regexp and GDB's regexp engine is not something
    # to hand attacker-influenced text.
    if rest and not re.fullmatch(r"[A-Za-z0-9_.:\- ]{1,80}", rest):
        return False, (
            f"'info {subcommand}' arguments must be plain identifiers, "
            f"not {rest!r}"
        )

    return True, None


__all__ = [
    "MAX_COMMAND_LENGTH",
    "allowed_commands",
    "allowed_info_subcommands",
    "validate_console_command",
]
