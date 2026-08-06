import pytest


class TestGeneratedRulesAreStructurallyValid:
    """A rule that looks fine and does not compile is worse than no rule.

    The strings section used to be emitted whenever ``strings`` was non-empty
    -- even if scoring filtered every candidate out, leaving an empty section
    -- while the imports block appended ``$impN`` identifiers WITHOUT emitting
    the header at all. With ``strings=[]`` and imports present the identifiers
    landed under ``meta:`` and the condition's ``all of them`` bound to nothing.
    """

    @staticmethod
    def _shape(rule: str) -> tuple[bool, bool, bool]:
        has_section = "    strings:" in rule
        has_ids = any(line.lstrip().startswith("$") for line in rule.splitlines())
        refs = any(tok in rule for tok in ("of them", "$s*"))
        return has_section, has_ids, refs

    @pytest.mark.parametrize("strictness", ["low", "medium", "high"])
    @pytest.mark.parametrize(
        "strings,imports",
        [
            ([], ["kernel32.dll"]),      # imports only -- the reported break
            ([], None),                  # nothing at all
            (["a", "b"], None),          # every candidate filtered by scoring
            (["CreateRemoteThread", "VirtualAllocEx"], None),
            (["CreateRemoteThread"], ["kernel32.dll"]),
        ],
    )
    def test_condition_never_references_undeclared_identifiers(
        self, strings, imports, strictness
    ):
        from src.tools.yara_tools import generate_yara_rule

        rule = generate_yara_rule(
            "probe", strings=strings, imports=imports, strictness=strictness
        )
        has_section, has_ids, refs = self._shape(rule)

        assert not (refs and not has_ids), (
            "condition references string identifiers that were never declared:\n" + rule
        )
        assert not (has_section and not has_ids), (
            "empty 'strings:' section is a yara syntax error:\n" + rule
        )
        assert not (has_ids and not has_section), (
            "string identifiers emitted outside a 'strings:' section:\n" + rule
        )
