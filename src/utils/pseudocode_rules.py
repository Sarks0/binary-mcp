"""
Pseudocode vulnerability rule registry.

Each rule runs as a regex against Ghidra-produced pseudocode (C-like text)
and surfaces a structured finding. Rules are deliberately conservative on
false negatives -- false positives are expected and are the point: this is
triage, not proof. A finding says "look here", not "this is exploitable".
"""

import re
from dataclasses import dataclass

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class PseudocodeRule:
    """One vulnerability / anti-pattern rule applied to decompiled C."""
    id: str
    cwe: str
    severity: str
    confidence: int
    description: str
    recommendation: str
    pattern: re.Pattern
    negative_pattern: re.Pattern | None = None


# Heuristics applied across findings to nudge confidence.
SCANNER_HINTS = re.compile(
    r"\b(re\.compile|RegExpr|RegExp|Regex|Pcre[A-Z_]?|pcre2?_compile|"
    r"regcomp|RtlRegex|FindPattern|MatchPattern)",
    re.IGNORECASE,
)
SINK_HINTS = re.compile(
    r"\b(memcpy|memmove|strcpy|strcat|wcscpy|wcscat|sprintf|system|popen|"
    r"WinExec|ShellExecute|CreateProcess)\s*\(",
)


class PseudocodeRules:
    """Database of CWE/anti-pattern rules applied to cached pseudocode."""

    def __init__(self):
        self.rules: list[PseudocodeRule] = self._load_default_rules()
        self._rules_by_id: dict[str, PseudocodeRule] = {r.id: r for r in self.rules}

    def get(self, rule_id: str) -> PseudocodeRule | None:
        return self._rules_by_id.get(rule_id)

    def filter(
        self,
        severity_floor: str = "low",
        rule_ids: list[str] | None = None,
    ) -> list[PseudocodeRule]:
        """Return rules at or above ``severity_floor``, optionally restricted to ``rule_ids``."""
        try:
            floor_idx = SEVERITY_ORDER.index(severity_floor.lower())
        except ValueError:
            floor_idx = SEVERITY_ORDER.index("low")

        selected = []
        for rule in self.rules:
            try:
                rule_idx = SEVERITY_ORDER.index(rule.severity.lower())
            except ValueError:
                rule_idx = SEVERITY_ORDER.index("low")
            if rule_idx < floor_idx:
                continue
            if rule_ids and rule.id not in rule_ids:
                continue
            selected.append(rule)
        return selected

    @staticmethod
    def _load_default_rules() -> list[PseudocodeRule]:
        """
        Curated rule set. Each rule declares a baseline confidence (0-100)
        which gets adjusted at scan time by per-finding context (corroboration
        from other rules, scanner-shaped functions, dangerous-sink presence,
        negative-pattern hits).
        """
        # (id, cwe, severity, confidence, description, recommendation, regex, negative_regex)
        # The regex-meta pattern is shared by credential-style rules to filter out
        # decompilation of the credential *scanner* itself.
        regex_meta = r"(?:\\b|\(\?[:!=<]|\[\^|[|\[\]]|\\{2,})"

        raw: list[tuple] = [
            (
                "CWE120_STRCPY", "CWE-120", "high", 60,
                "Use of strcpy/strcat without explicit length bounds",
                "Replace with strncpy_s/strlcpy or equivalent bounded variant.",
                r"\b(strcpy|strcat|wcscpy|wcscat|lstrcpy[AW]?|lstrcat[AW]?)\s*\(",
                None,
            ),
            (
                "CWE120_SPRINTF_UNBOUNDED", "CWE-120", "high", 55,
                "sprintf/wsprintf without length cap -- caller trusts format output size",
                "Use snprintf/_snprintf_s with an explicit destination size.",
                r"\b(sprintf|vsprintf|wsprintf[AW]?)\s*\(",
                None,
            ),
            (
                "CWE120_GETS", "CWE-120", "critical", 95,
                "gets() always reads unbounded input",
                "Replace with fgets() or getline().",
                r"\bgets\s*\(",
                None,
            ),
            (
                "CWE120_MEMCPY_SIGNED_LEN", "CWE-120", "medium", 50,
                "memcpy/memmove with a signed/int-typed length -- possible negative-to-size_t wrap",
                "Cast/validate length as size_t and bound-check against destination size.",
                r"\b(memcpy|memmove|RtlCopyMemory)\s*\([^,]+,[^,]+,\s*\(?\s*(int|short|char|long)\b",
                None,
            ),
            (
                "CWE134_FORMAT_STRING", "CWE-134", "high", 65,
                "printf-family call with a non-literal format argument -- classic format-string bug",
                "Pass a literal format string; route user data through %s arguments.",
                r"\b(printf|fprintf|vprintf|vfprintf|syslog)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
                None,
            ),
            (
                "CWE190_MALLOC_ARITHMETIC", "CWE-190", "medium", 40,
                "Arithmetic inside malloc/calloc size argument -- potential integer overflow before allocation",
                "Validate both operands against SIZE_MAX / desired bound before multiplying.",
                r"\b(malloc|calloc|HeapAlloc|VirtualAlloc)\s*\([^)]*[*+][^)]*\)",
                None,
            ),
            (
                "CWE367_TOCTOU_ACCESS_OPEN", "CWE-367", "medium", 55,
                "access/stat followed by open -- time-of-check to time-of-use race",
                "Open-then-check (fstat on the fd) instead of check-then-open.",
                r"\b(access|stat|lstat)\s*\([^;]{1,200};[^;]{0,400}\b(open|fopen|CreateFile[AW]?)\s*\(",
                None,
            ),
            (
                "CWE415_DOUBLE_FREE", "CWE-415", "high", 70,
                "Same pointer freed twice in the visible window -- likely double-free",
                "NULL the pointer immediately after free; add ownership discipline.",
                r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)[^;]*;(?:[^;]{0,400};)?\s*free\s*\(\s*\1\s*\)",
                None,
            ),
            (
                "CWE476_NULL_DEREF_POST_MALLOC", "CWE-476", "medium", 50,
                "Pointer dereference immediately after malloc without a NULL check",
                "Check the returned pointer against NULL before use.",
                r"=\s*(malloc|calloc|realloc)\s*\([^;]{1,200};\s*\*",
                None,
            ),
            (
                "CWE78_COMMAND_INJECTION", "CWE-78", "critical", 75,
                "system/popen/exec/ShellExecute with non-literal command argument",
                "Use execve with argv array; never pass concatenated user data to a shell.",
                r"\b(system|popen|WinExec|ShellExecute[AW]?|_?execl[pe]?|_?execv[pe]?)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]",
                None,
            ),
            (
                "CWE78_CREATEPROCESS_NONLITERAL", "CWE-78", "high", 55,
                "CreateProcess with non-literal command line -- suspect if command data is attacker-influenced",
                "Pass a fully-qualified application name; audit command-line construction.",
                r"\bCreateProcess[AW]?\s*\([^)]*,[^,]*[a-zA-Z_][a-zA-Z0-9_]*\s*,",
                None,
            ),
            (
                "CWE131_SIZEOF_TIMES_COUNT", "CWE-131", "low", 35,
                "Allocation of sizeof(T)*N -- verify N is bounded (overflow check missing)",
                "Bound-check N against SIZE_MAX/sizeof(T).",
                r"\b(malloc|calloc|HeapAlloc)\s*\([^)]*sizeof\s*\([^)]+\)\s*\*\s*[A-Za-z_][A-Za-z0-9_]*",
                None,
            ),
            (
                "CWE798_HARDCODED_PASSWORD", "CWE-798", "medium", 30,
                "String literal resembling a password/secret hardcoded in decompilation -- "
                "this rule is noisy by design; corroborate before reporting",
                "Load secrets from configuration/secret store, never embed in code.",
                r'"[^"]*(pass(word)?|secret|api[_-]?key|auth[_-]?token|bearer)[^"]*"\s*',
                # If the literal contains regex meta characters it is almost certainly
                # a credential *detector*, not a credential.
                regex_meta,
            ),
            (
                "CWE798_AWS_ACCESS_KEY", "CWE-798", "critical", 90,
                "AWS access-key-shaped literal -- AKIA + 16 base32 characters",
                "Rotate immediately; load credentials from IAM role / env / SSO.",
                r'"AKIA[0-9A-Z]{16}"',
                None,
            ),
            (
                "CWE798_GITHUB_TOKEN", "CWE-798", "critical", 90,
                "GitHub-style PAT/OAuth token literal (ghp_/gho_/ghs_/ghu_)",
                "Rotate the token via GitHub UI; never commit PATs to artifacts.",
                r'"gh[opsu]_[A-Za-z0-9]{36,}"',
                None,
            ),
            (
                "CWE798_STRIPE_SECRET", "CWE-798", "critical", 90,
                "Stripe live secret key literal (sk_live_)",
                "Rotate via the Stripe dashboard; load from secret store.",
                r'"sk_live_[A-Za-z0-9]{20,}"',
                None,
            ),
            (
                "CWE798_JWT_TOKEN", "CWE-798", "high", 80,
                "JWT-shaped literal -- header.payload.signature with eyJ prefix",
                "If genuine, rotate the signing key; do not embed bearer tokens in binaries.",
                r'"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"',
                None,
            ),
            (
                "CWE121_STACK_COPY_NO_BOUNDS", "CWE-121", "medium", 50,
                "Stack-buffer copy without visible bound check (strncpy/memcpy of stack array)",
                "Ensure source length ≤ destination size; prefer safer wrappers.",
                r"\b(strncpy|memcpy|RtlCopyMemory)\s*\(\s*(local_|auStack|acStack|l?u?Stack)",
                None,
            ),
            (
                "CWE676_DANGEROUS_FN", "CWE-676", "low", 30,
                "Use of historically dangerous function family",
                "Audit usage; prefer safer library equivalents where available.",
                r"\b(scanf|sscanf|fscanf|alloca|_alloca|tmpnam|mktemp)\s*\(",
                None,
            ),
            (
                "CWE416_USE_AFTER_FREE", "CWE-416", "high", 65,
                "Pointer used after free in the visible window",
                "NULL the pointer at free; restructure ownership so freed memory is unreachable.",
                r"\bfree\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)[^;]*;(?:[^;]{0,400};){0,4}"
                r"[^;]*\b\1\s*(?:->|\[)|\*\s*\1\b",
                None,
            ),
            (
                "CWE805_MEMCPY_HEADER_DRIVEN_LEN", "CWE-805", "high", 70,
                "memcpy/memmove length comes from a struct field or pointer deref -- "
                "classic 'attacker-controlled size from packet' shape",
                "Validate the size against the destination capacity AND the remaining input "
                "before copying.",
                r"\b(memcpy|memmove|RtlCopyMemory|RtlMoveMemory)\s*\("
                r"[^,]+,[^,]+,\s*"
                r"(?:\*\s*[A-Za-z_]|\(?\s*[A-Za-z_][A-Za-z0-9_]*\s*->\s*[A-Za-z_]"
                r"|[A-Za-z_][A-Za-z0-9_]*\s*\[)",
                None,
            ),
            (
                "CWE190_HEADER_LEN_TO_ALLOC", "CWE-190", "high", 70,
                "Allocation size derived from a struct/deref field with arithmetic -- "
                "header-length integer overflow before alloc",
                "Range-check the length field BEFORE arithmetic; reject sizes that would overflow size_t.",
                r"\b(malloc|calloc|HeapAlloc|RtlAllocateHeap|VirtualAlloc|new\b)\s*\("
                r"[^)]*"
                r"(?:[A-Za-z_][A-Za-z0-9_]*\s*->\s*[A-Za-z_]|\*\s*[A-Za-z_])"
                r"[^)]*[*+][^)]*\)",
                None,
            ),
            (
                "CWE401_REALLOC_SHADOW", "CWE-401", "medium", 60,
                "realloc result assigned back to the same pointer -- on failure the original "
                "pointer is leaked and may also be left dangling",
                "Use a temporary: tmp = realloc(p, n); if (tmp) p = tmp; else handle_failure().",
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:realloc|HeapReAlloc)\s*\(\s*\1\b",
                None,
            ),
            (
                "CWE242_ALLOCA_VARIABLE", "CWE-242", "high", 60,
                "Variable-size _alloca/alloca -- attacker-sized stack growth enables stack pivots and exhaustion",
                "Replace with malloc + free, or cap the size with a hard-coded ceiling.",
                r"\b_?alloca\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                None,
            ),
            (
                "CWE242_VIRTUALALLOC_RWX", "CWE-242", "high", 80,
                "Memory page allocated with PAGE_EXECUTE_READWRITE -- RWX is a strong code-injection signal",
                "Allocate RW, then VirtualProtect to RX. Avoid RWX outside JIT engines.",
                r"\b(VirtualAlloc(?:Ex)?|NtAllocateVirtualMemory|VirtualProtect(?:Ex)?)\s*\("
                r"[^)]*PAGE_EXECUTE_READWRITE",
                None,
            ),
            (
                "CWE193_NULL_TERM_OFF_BY_ONE", "CWE-193", "medium", 50,
                "Null terminator written at index equal to a length variable -- classic off-by-one if buffer was sized exactly len",
                "Allocate len+1 bytes, or write the terminator at len-1 after a bounded copy.",
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([A-Za-z_][A-Za-z0-9_]*(?:_len|len|Length|size|Size))\s*\]"
                r"\s*=\s*(?:0|'\\0'|L?\"\\0\")",
                None,
            ),
            (
                "CWE822_DEREF_USER_OFFSET", "CWE-822", "medium", 35,
                "Pointer arithmetic with a non-constant offset followed by deref -- bounds may not be enforced",
                "Verify the offset is within the buffer length before dereferencing.",
                r"\*\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                None,
            ),
            (
                "CWE125_STRLEN_UNTRUSTED_PTR", "CWE-125", "low", 40,
                "strlen on a pointer derived from input -- if the buffer isn't NUL-terminated this is an OOB read",
                "Use strnlen with the known buffer length; never trust input to be terminated.",
                r"\bstrlen\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*->\s*|\*\s*)",
                None,
            ),
        ]

        rules: list[PseudocodeRule] = []
        for rid, cwe, sev, conf, desc, rec, regex, neg in raw:
            rules.append(
                PseudocodeRule(
                    id=rid,
                    cwe=cwe,
                    severity=sev,
                    confidence=conf,
                    description=desc,
                    recommendation=rec,
                    pattern=re.compile(regex, re.MULTILINE | re.DOTALL),
                    negative_pattern=(
                        re.compile(neg, re.MULTILINE | re.DOTALL)
                        if neg else None
                    ),
                )
            )
        return rules


def find_line_excerpt(pseudocode: str, match: re.Match, context_chars: int = 120) -> str:
    """
    Return a short single-line excerpt surrounding a match for display.

    Collapses newlines/whitespace so findings fit on one line.
    """
    start = max(0, match.start() - context_chars // 2)
    end = min(len(pseudocode), match.end() + context_chars // 2)
    excerpt = pseudocode[start:end]
    excerpt = re.sub(r"\s+", " ", excerpt).strip()
    if start > 0:
        excerpt = "…" + excerpt
    if end < len(pseudocode):
        excerpt = excerpt + "…"
    return excerpt


NEGATIVE_PATTERN_PENALTY = 40


def scan_text(pseudocode: str, rules: list[PseudocodeRule]) -> list[dict]:
    """
    Apply a rule set to one pseudocode string, return a list of findings.

    Each finding has: rule_id, cwe, severity, confidence (rule baseline,
    adjusted down if the rule's negative_pattern matched the literal),
    description, recommendation, excerpt. Cross-rule corroboration and
    function-shape adjustments happen in the caller.
    """
    findings: list[dict] = []
    if not pseudocode:
        return findings

    for rule in rules:
        for match in rule.pattern.finditer(pseudocode):
            confidence = rule.confidence
            if rule.negative_pattern and rule.negative_pattern.search(match.group(0)):
                confidence = max(0, confidence - NEGATIVE_PATTERN_PENALTY)
            findings.append({
                "rule_id": rule.id,
                "cwe": rule.cwe,
                "severity": rule.severity,
                "confidence": confidence,
                "description": rule.description,
                "recommendation": rule.recommendation,
                "excerpt": find_line_excerpt(pseudocode, match),
            })
    return findings


CORROBORATION_BONUS = 30
SCANNER_PENALTY = 30
SINK_BONUS = 20


def adjust_confidences(findings: list[dict], pseudocode: str) -> None:
    """
    Mutate findings in place to apply per-function context adjustments.

    Call this once per function with the findings collected from that
    function's pseudocode.
    """
    if not findings:
        return
    is_scanner = bool(SCANNER_HINTS.search(pseudocode))
    has_sink = bool(SINK_HINTS.search(pseudocode))
    distinct_rules = {f["rule_id"] for f in findings}
    has_corroboration = len(distinct_rules) >= 2

    for f in findings:
        c = f["confidence"]
        if has_corroboration:
            c += CORROBORATION_BONUS
        if is_scanner and f["rule_id"].startswith("CWE798_HARDCODED_PASSWORD"):
            # Only the noisy generic credential rule gets penalised when
            # it lands in a scanner -- the high-signal token-format rules
            # stay confident.
            c -= SCANNER_PENALTY
        if has_sink and f["cwe"] in ("CWE-120", "CWE-121", "CWE-805", "CWE-78"):
            c += SINK_BONUS
        f["confidence"] = max(0, min(100, c))
