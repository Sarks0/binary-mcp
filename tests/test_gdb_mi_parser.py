"""Tests for the GDB/MI output parser.

Fixtures are real records captured from GNU gdb 15.1 (Ubuntu
15.1-1ubuntu1~24.04.1) driving PIE, non-PIE, stripped-static and forking
x86-64 ELF targets. No GDB installation is needed to run them, so the whole
grammar is covered on the Windows and macOS CI runners too.
"""

from __future__ import annotations

import pytest

from src.engines.dynamic.gdb.mi_parser import (
    MIParseError,
    RecordKind,
    parse_line,
    parse_lines,
    parse_value,
)

BREAK_INSERT = (
    '^done,bkpt={number="1",type="breakpoint",disp="keep",enabled="y",'
    'addr="0x00000000000011d4",func="target",file="t.c",fullname="/tmp/t.c",'
    'line="4",thread-groups=["i1"],times="0",original-location="target"}'
)

STOPPED_BREAKPOINT = (
    '*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",'
    'frame={addr="0x00005555555551d4",func="target",args=[{name="x",value="1"}],'
    'file="t.c",fullname="/tmp/t.c",line="4",arch="i386:x86-64"},'
    'thread-id="1",stopped-threads="all",core="1"'
)

STOPPED_SYSCALL = (
    '*stopped,reason="syscall-entry",disp="keep",bkptno="1",'
    'syscall-number="257",syscall-name="openat",'
    'frame={addr="0x00007ffff7feab71",func="__GI___open64_nocancel",args=[]},'
    'thread-id="1",stopped-threads="all",core="3"'
)

STOPPED_SIGINT = (
    '*stopped,reason="signal-received",signal-name="SIGINT",'
    'signal-meaning="Interrupt",'
    'frame={addr="0x0000555555555139",func="main",args=[],arch="i386:x86-64"},'
    'thread-id="1",stopped-threads="all",core="0"'
)

LIBRARY_LOADED = (
    '=library-loaded,id="/lib64/ld-linux-x86-64.so.2",'
    'target-name="/lib64/ld-linux-x86-64.so.2",'
    'host-name="/lib64/ld-linux-x86-64.so.2",symbols-loaded="0",'
    'thread-group="i1",ranges=[{from="0x00007ffff7fc6000",to="0x00007ffff7ff0195"}]'
)

REGISTER_VALUES = (
    '^done,register-values=[{number="0",value="0x1"},'
    '{number="1",value="0x7fffffffcc88"},{number="2",value="0x7ffff7d16724"}]'
)

# -data-disassemble in source mode: a list of results with a REPEATED name.
DISASSEMBLE_SOURCE = (
    '^done,asm_insns=[src_and_asm_line={line="4",file="t.c",'
    'line_asm_insn=[{address="0x00005555555551d4",func-name="target",offset="11",'
    'opcodes="8b 55 fc",inst="mov    -0x4(%rbp),%edx"}]},'
    'src_and_asm_line={line="5",file="t.c",'
    'line_asm_insn=[{address="0x00005555555551df",func-name="main",offset="0",'
    'opcodes="f3 0f 1e fa",inst="endbr64"}]}]'
)

READ_MEMORY = (
    '^done,memory=[{begin="0x00005555555551d4",'
    'offset="0x0000000000000000",end="0x00005555555551dc",contents="8b55fc89d001c001"}]'
)


def test_break_insert_result():
    rec = parse_line(BREAK_INSERT)
    assert rec.kind is RecordKind.RESULT
    assert rec.klass == "done"
    assert rec.token is None
    bkpt = rec.results["bkpt"]
    assert bkpt["number"] == "1"
    assert bkpt["addr"] == "0x00000000000011d4"
    assert bkpt["thread-groups"] == ["i1"]
    assert bkpt["original-location"] == "target"


def test_running_and_exit_have_no_results():
    assert parse_line("^running").klass == "running"
    assert parse_line("^running").results == {}
    assert parse_line("^exit").klass == "exit"
    assert parse_line("^connected").klass == "connected"


def test_leading_token_is_captured():
    rec = parse_line('1234^done,value="0x1"')
    assert rec.token == 1234
    assert rec.klass == "done"
    assert rec.results["value"] == "0x1"


def test_register_values_list_of_tuples():
    rec = parse_line(REGISTER_VALUES)
    values = rec.results["register-values"]
    assert len(values) == 3
    # Register 16 is RIP on x86-64; 0 is RAX. Numbers, not names -- the bridge
    # has to map them via -data-list-register-names.
    assert values[0] == {"number": "0", "value": "0x1"}


def test_read_memory_contents():
    rec = parse_line(READ_MEMORY)
    block = rec.results["memory"][0]
    assert block["contents"] == "8b55fc89d001c001"
    assert bytes.fromhex(block["contents"])[:3] == b"\x8b\x55\xfc"


def test_error_record_exposes_message():
    rec = parse_line('^error,msg="No registers."')
    assert rec.is_error
    assert rec.error_message == "No registers."


def test_error_message_with_embedded_escaped_quotes():
    # Verbatim from -break-insert against a stripped, statically linked ELF.
    line = r'^error,msg="No symbol table is loaded.  Use the \"file\" command."'
    rec = parse_line(line)
    assert rec.is_error
    assert rec.error_message == 'No symbol table is loaded.  Use the "file" command.'


def test_non_error_records_have_no_error_message():
    assert parse_line("^done").error_message is None
    assert not parse_line(STOPPED_SIGINT).is_error


def test_stopped_breakpoint_hit():
    rec = parse_line(STOPPED_BREAKPOINT)
    assert rec.kind is RecordKind.EXEC
    assert rec.is_async
    assert rec.klass == "stopped"
    assert rec.results["reason"] == "breakpoint-hit"
    assert rec.results["bkptno"] == "1"
    frame = rec.results["frame"]
    assert frame["func"] == "target"
    assert frame["args"] == [{"name": "x", "value": "1"}]


def test_stopped_syscall_entry_carries_number_and_name():
    rec = parse_line(STOPPED_SYSCALL)
    assert rec.results["reason"] == "syscall-entry"
    assert rec.results["syscall-number"] == "257"
    assert rec.results["syscall-name"] == "openat"
    assert rec.results["frame"]["args"] == []


def test_stopped_signal_received():
    rec = parse_line(STOPPED_SIGINT)
    assert rec.results["reason"] == "signal-received"
    assert rec.results["signal-name"] == "SIGINT"


def test_running_async_record():
    rec = parse_line('*running,thread-id="all"')
    assert rec.kind is RecordKind.EXEC
    assert rec.klass == "running"
    assert rec.results["thread-id"] == "all"


def test_notify_records():
    rec = parse_line(LIBRARY_LOADED)
    assert rec.kind is RecordKind.NOTIFY
    assert rec.klass == "library-loaded"
    # The load range is what supplies a PIE module's runtime base.
    assert rec.results["ranges"] == [
        {"from": "0x00007ffff7fc6000", "to": "0x00007ffff7ff0195"}
    ]

    added = parse_line('=thread-group-added,id="i1"')
    assert added.kind is RecordKind.NOTIFY
    assert added.results == {"id": "i1"}


def test_status_async_record():
    rec = parse_line('+download,section="text",section-sent="512"')
    assert rec.kind is RecordKind.STATUS
    assert rec.is_async


def test_console_stream_unescapes_text():
    rec = parse_line(r'~"Breakpoint 1, target (x=1) at t.c:4\n"')
    assert rec.kind is RecordKind.CONSOLE
    assert rec.is_stream
    assert rec.text == "Breakpoint 1, target (x=1) at t.c:4\n"


def test_log_stream_with_tab_escape():
    rec = parse_line(r'&"warning: 39\t../sysdeps/open64.c: No such file\n"')
    assert rec.kind is RecordKind.LOG
    assert rec.text == "warning: 39\t../sysdeps/open64.c: No such file\n"


def test_target_stream():
    rec = parse_line(r'@"parent done\n"')
    assert rec.kind is RecordKind.TARGET
    assert rec.text == "parent done\n"


def test_prompt_and_blank_lines():
    assert parse_line("(gdb)").kind is RecordKind.PROMPT
    assert parse_line("(gdb) ").kind is RecordKind.PROMPT
    assert parse_line("").kind is RecordKind.RAW


def test_non_mi_output_is_raw_not_an_error():
    # GDB prints this straight to stdout when a console command asks to confirm.
    line = "Kill the program being debugged? (y or n) [answered Y; input not from terminal]"
    rec = parse_line(line)
    assert rec.kind is RecordKind.RAW
    assert rec.text == line


def test_inferior_stdout_is_raw():
    rec = parse_line("uid=0(root) gid=0(root) groups=0(root)")
    assert rec.kind is RecordKind.RAW


def test_empty_tuple_and_list():
    assert parse_value("{}") == {}
    assert parse_value("[]") == []
    assert parse_line("^done,a={},b=[]").results == {"a": {}, "b": []}


def test_list_of_bare_values():
    assert parse_value('["i1","i2"]') == ["i1", "i2"]


def test_list_of_results_preserves_repeated_names():
    """MI repeats names in lists; merging into a dict would drop rows."""
    parsed = parse_value('[bkpt={number="1"},bkpt={number="2"}]')
    assert parsed == [{"bkpt": {"number": "1"}}, {"bkpt": {"number": "2"}}]


def test_disassemble_source_mode_keeps_both_lines():
    rec = parse_line(DISASSEMBLE_SOURCE)
    rows = rec.results["asm_insns"]
    assert len(rows) == 2
    assert rows[0]["src_and_asm_line"]["line"] == "4"
    assert rows[1]["src_and_asm_line"]["line"] == "5"
    first_insn = rows[0]["src_and_asm_line"]["line_asm_insn"][0]
    assert first_insn["inst"] == "mov    -0x4(%rbp),%edx"
    assert first_insn["func-name"] == "target"


def test_repeated_name_at_record_level_becomes_a_list():
    rec = parse_line('^done,bkpt={number="1"},bkpt={number="2"}')
    assert rec.results["bkpt"] == [{"number": "1"}, {"number": "2"}]


def test_deeply_nested_structures():
    rec = parse_line('^done,a={b=[{c={d=["e"]}}]}')
    assert rec.results["a"]["b"][0]["c"]["d"] == ["e"]


def test_value_containing_equals_and_angle_brackets():
    # -data-evaluate-expression "$pc" returns an annotated address.
    rec = parse_line('^done,value="0x5555555551d4 <target+11>"')
    assert rec.results["value"] == "0x5555555551d4 <target+11>"


def test_quoted_string_containing_equals_is_not_a_result():
    assert parse_value('["a=b","c=d"]') == ["a=b", "c=d"]


def test_breakpoint_table_shape():
    line = (
        '^done,BreakpointTable={nr_rows="1",nr_cols="6",'
        'hdr=[{width="7",alignment="-1",col_name="number",colhdr="Num"},'
        '{width="14",alignment="-1",col_name="type",colhdr="Type"}],'
        'body=[bkpt={number="1",type="breakpoint",addr="0x0000000000401776"}]}'
    )
    table = parse_line(line).results["BreakpointTable"]
    assert table["nr_rows"] == "1"
    assert len(table["hdr"]) == 2
    assert table["body"][0]["bkpt"]["addr"] == "0x0000000000401776"


def test_break_delete_by_address_reports_done_but_does_not_delete():
    """Regression fixture for the silent no-op found against GDB 15.1.

    `-break-delete *0xADDR` answers ^done and leaves the breakpoint armed;
    only `-break-delete <number>` removes it. The parser must report both
    faithfully so the bridge can catch the discrepancy by reading back.
    """
    assert parse_line("^done").klass == "done"

    still_there = parse_line('^done,BreakpointTable={nr_rows="1",body=[bkpt={number="1"}]}')
    assert still_there.results["BreakpointTable"]["nr_rows"] == "1"

    gone = parse_line('^done,BreakpointTable={nr_rows="0",body=[]}')
    assert gone.results["BreakpointTable"]["nr_rows"] == "0"


def test_backslash_and_quote_escapes():
    assert parse_value(r'"a\\b"') == "a\\b"
    assert parse_value(r'"say \"hi\""') == 'say "hi"'


def test_control_character_escapes():
    assert parse_value(r'"\n\t\r\f\b\a\v"') == "\n\t\r\f\b\a\v"


def test_octal_escapes_decode_to_bytes_then_utf8():
    """GDB escapes non-ASCII bytes octally; they must rejoin as one character."""
    assert parse_value(r'"caf\303\251"') == "café"
    assert parse_value(r'"\101\102\103"') == "ABC"


def test_hex_escape():
    assert parse_value(r'"\x41\x42"') == "AB"


def test_octal_escape_stops_at_three_digits():
    # \1011 is octal 101 ("A") followed by a literal "1".
    assert parse_value(r'"\1011"') == "A1"


def test_invalid_utf8_is_replaced_not_raised():
    # A lone continuation byte cannot be valid UTF-8; a malicious filename can
    # contain one, and it must not take the parser down.
    assert parse_value(r'"\377"') == "\ufffd"


def test_windows_style_path_backslashes():
    assert parse_value(r'"C:\\Windows\\System32"') == "C:\\Windows\\System32"


def test_unknown_escape_keeps_the_literal_character():
    assert parse_value(r'"\q"') == "q"


@pytest.mark.parametrize(
    "line",
    [
        '^done,bkpt={number="1"',          # unterminated tuple
        '^done,list=["a"',                  # unterminated list
        '^done,msg="unterminated',          # unterminated string
        "^done,novalue",                    # result with no '='
        '^done,=  "1"',                     # empty result name
        "^",                                # no result class
        '^bogus,a="1"',                     # unknown result class
        r'~"trailing" junk',                # data after a stream string
    ],
)
def test_malformed_records_raise(line):
    with pytest.raises(MIParseError):
        parse_line(line)


def test_parse_value_rejects_trailing_data():
    with pytest.raises(MIParseError):
        parse_value('"a" "b"')


def test_parse_lines_over_a_captured_session_fragment():
    """The exact interleaving seen when -exec-interrupt is issued async."""
    stream = "\n".join([
        "-exec-interrupt",
        "^done",
        "(gdb)",
        r'~"\nProgram"',
        r'~" received signal SIGINT, Interrupt.\n"',
        STOPPED_SIGINT,
        '^done,register-values=[{number="16",value="0x555555555139"}]',
        "(gdb)",
    ])
    records = parse_lines(stream)
    kinds = [r.kind for r in records]

    # The echoed command is not MI and must not derail the stream.
    assert kinds[0] is RecordKind.RAW
    assert kinds[1] is RecordKind.RESULT
    assert kinds[2] is RecordKind.PROMPT
    assert kinds[3] is RecordKind.CONSOLE

    # ^done for the interrupt arrives BEFORE *stopped -- the reason the bridge
    # needs an async event queue rather than request/response.
    assert records[1].klass == "done"
    assert records[5].results["reason"] == "signal-received"
    assert records[6].results["register-values"][0]["value"] == "0x555555555139"
