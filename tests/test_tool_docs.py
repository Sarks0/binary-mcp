"""Tests for src/utils/tool_docs.py: docstrings shaped for the model."""

from types import SimpleNamespace

from src.utils.tool_docs import shape_tool_docs

DOC = """Decompile a function.

Longer explanation that stays.

Args:
    binary_path: Path to analyzed binary
    wait: Whether to block.

        Second paragraph of the wait docs.
    start_address / end_address: Hex bounds
        restricting the run.
    ghost: Documents a parameter the tool no longer has

Returns:
    Pseudocode, or a job_id.

Note:
    Keep this caveat.

Example:
    decompile_function("/x", "main")
"""


def _tool(doc=DOC, params=("binary_path", "wait", "start_address", "end_address")):
    return SimpleNamespace(
        description=doc,
        parameters={"type": "object", "properties": {p: {"type": "string"} for p in params}},
    )


def _shape(tool):
    shape_tool_docs({"t": tool})
    return tool


def test_args_become_parameter_descriptions():
    props = _shape(_tool()).parameters["properties"]
    assert props["binary_path"]["description"] == "Path to analyzed binary"
    assert props["wait"]["description"] == (
        "Whether to block.\n\nSecond paragraph of the wait docs."
    )


def test_an_entry_for_two_parameters_documents_both():
    props = _shape(_tool()).parameters["properties"]
    assert props["start_address"]["description"] == "Hex bounds restricting the run."
    assert props["end_address"]["description"] == "Hex bounds restricting the run."


def test_restating_sections_are_dropped_and_guidance_stays():
    description = _shape(_tool()).description
    assert description.startswith("Decompile a function.\n\nLonger explanation that stays.")
    assert "Returns:" not in description and "job_id" not in description
    assert "Example:" not in description and "decompile_function(" not in description
    assert "Note:\n    Keep this caveat." in description


def test_an_entry_naming_no_parameter_is_kept_in_the_description():
    description = _shape(_tool()).description
    assert "Args:\n    ghost: Documents a parameter" in description
    assert "binary_path:" not in description


def test_an_existing_schema_description_wins():
    tool = _tool()
    tool.parameters["properties"]["binary_path"]["description"] = "From Field()"
    assert _shape(tool).parameters["properties"]["binary_path"]["description"] == "From Field()"


def test_plain_docstring_is_unchanged():
    assert _shape(_tool(doc="List functions.")).description == "List functions."


def test_list_items_keep_their_line_breaks():
    doc = "Do it.\n\nArgs:\n    section: Which part:\n        - metadata: only metadata\n        - tools: every call\n"
    props = _shape(_tool(doc=doc, params=("section",))).parameters["properties"]
    assert props["section"]["description"] == (
        "Which part:\n- metadata: only metadata\n- tools: every call"
    )
