"""Tests for src/utils/decompiler_caveats.py."""

from src.utils.decompiler_caveats import (
    MARKER_PREFIX,
    annotate,
    find_caveats,
    render_c_block,
)

SAMPLE = """\
/* WARNING: Could not recover jumptable at 0x1800012a0. Too many branches */

undefined8 FUN_180001000(longlong param_1)
{
  undefined8 unaff_RBX;
  longlong in_GS_OFFSET;
  int iVar1;
  char in_buffer[16];

  iVar1 = wsprintfW(local_28, L"%s %d %d %d");
  _guard_dispatch_icall(*(undefined8 *)(param_1 + 8));
  iVar1 = FUN_180002000();
  if (extraout_EAX == 0) {
    __security_check_cookie(local_10 ^ (ulonglong)auStack_48);
  }
  return unaff_RBX;
}
"""


def _kinds(pseudo):
    return {(c.kind, c.detail) for c in find_caveats(pseudo)}


def test_finds_every_artifact_kind():
    kinds = _kinds(SAMPLE)
    assert ("unaffected-return", "unaff_RBX") in kinds
    assert ("unaffected-register", "unaff_RBX") in kinds  # the declaration line
    assert ("extraout-register", "extraout_EAX") in kinds
    assert ("undeclared-input", "in_GS_OFFSET") in kinds
    assert ("variadic-call", "wsprintfW") in kinds
    assert ("compiler-helper", "_guard_dispatch_icall") in kinds
    assert ("compiler-helper", "__security_check_cookie") in kinds
    warnings = [c for c in find_caveats(SAMPLE) if c.kind == "decompiler-warning"]
    assert len(warnings) == 1 and "case bodies are missing" in warnings[0].meaning


def test_user_variables_named_in_are_not_flagged():
    assert not any(d == "in_buffer" for _, d in _kinds(SAMPLE))


def test_va_list_variants_are_not_variadic():
    assert _kinds("vswprintf(buf, fmt, args);") == set()
    assert _kinds("_vsnwprintf(buf, 10, fmt, args);") == set()


def test_import_and_thunk_prefixes_still_match():
    assert ("variadic-call", "DbgPrintEx") in _kinds("__imp_DbgPrintEx(0x4d, 0, fmt);")
    assert ("variadic-call", "sprintf") in _kinds("thunk_sprintf(buf, fmt);")


def test_undeclared_input_stack_and_register_forms():
    kinds = _kinds("x = in_stack_00000028 + in_RAX + in_XMM0_Qa;")
    assert {d for _, d in kinds} == {"in_stack_00000028", "in_RAX", "in_XMM0_Qa"}


def test_bad_instruction_data():
    assert ("bad-instruction", "halt_baddata()") in _kinds("  halt_baddata();")


def test_clean_code_is_untouched():
    clean = "int f(int a)\n{\n  return a + 1;\n}\n"
    annotated, summary = annotate(clean)
    assert annotated == clean
    assert summary == []
    assert render_c_block(clean) == ["```c", clean, "```"]


def test_inline_markers_land_on_the_misleading_lines():
    annotated, summary = annotate(SAMPLE)
    lines = annotated.splitlines()
    ret = next(line for line in lines if line.strip().startswith("return unaff_RBX"))
    assert MARKER_PREFIX in ret and "not a real return value" in ret
    call = next(line for line in lines if "wsprintfW(" in line)
    assert "argument list may be truncated" in call
    cfg = next(line for line in lines if "_guard_dispatch_icall(" in line)
    assert "compiler-inserted" in cfg
    # A plain declaration of unaff_RBX gets no inline marker, only a summary row.
    decl = next(line for line in lines if line.strip() == "undefined8 unaff_RBX;")
    assert MARKER_PREFIX not in decl
    assert summary[0].startswith("**Decompiler caveats (")


def test_annotate_is_idempotent():
    once, _ = annotate(SAMPLE)
    twice, _ = annotate(once)
    assert once == twice


def test_summary_is_capped():
    many = "\n".join(f"x = unaff_R{i};" for i in range(30))
    _, summary = annotate(many, max_summary=5)
    assert len(summary) == 1 + 5 + 1
    assert summary[-1] == "- ... and 25 more"


def test_render_c_block_unfenced_keeps_summary():
    out = render_c_block(SAMPLE, fence=False)
    assert out[0].startswith("/* WARNING")
    assert any(line.startswith("**Decompiler caveats") for line in out)


# Regressions from the branch code review


def test_sample_text_cannot_suppress_its_own_caveat():
    """Ghidra reproduces the binary's string constants, so a sample can put
    the marker prefix on a line. It used to skip annotating that line while
    the summary still counted the artifact -- the two then disagreed."""
    pseudo = (
        'char *decoy = "/* [caveat] nothing to see */";\n'
        'return unaff_RBX;  // "/* [caveat] " appears above\n'
    )
    annotated, summary = annotate(pseudo)

    lines = annotated.splitlines()
    assert "is a decompiler artifact" in lines[1]
    assert any("unaff_RBX" in s for s in summary)


def test_a_marker_on_the_decoy_line_does_not_stop_its_own_annotation():
    pseudo = 'x = unaff_EBP + 1;  /* [caveat] injected */\n'
    annotated, _ = annotate(pseudo)
    # Our marker is re-derived, not trusted: the line keeps one marker, and
    # the injected text is not carried forward as if we had written it.
    assert annotated.count(MARKER_PREFIX) <= 1
    assert "injected" not in annotated


def test_annotating_twice_is_idempotent():
    pseudo = "return unaff_RBX;\n"
    once, _ = annotate(pseudo)
    twice, _ = annotate(once)
    assert twice == once


def test_every_occurrence_still_gets_its_own_marker():
    """The single-pass rewrite must not lose the per-line grouping: the
    deduped summary keeps the first occurrence, the body marks them all."""
    pseudo = "return unaff_RBX;\nfoo();\nreturn unaff_RBX;\n"
    annotated, summary = annotate(pseudo)
    lines = annotated.splitlines()
    assert MARKER_PREFIX in lines[0] and MARKER_PREFIX in lines[2]
    assert MARKER_PREFIX not in lines[1]
    assert len([s for s in summary if "unaff_RBX" in s]) == 1
