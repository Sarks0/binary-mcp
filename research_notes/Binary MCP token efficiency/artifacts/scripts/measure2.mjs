import { createRequire } from 'node:module';
import path from 'node:path';
const NM = process.argv[2];
const require = createRequire(path.join(NM, 'x.js'));
const o = require(path.join(NM, 'gpt-tokenizer/cjs/encoding/o200k_base.js'));
const c = require(path.join(NM, 'gpt-tokenizer/cjs/encoding/cl100k_base.js'));
const show = (l, s) => console.log(`${l.padEnd(58)} chars=${String(s.length).padStart(6)} o200k=${String(o.encode(s).length).padStart(6)} cl100k=${String(c.encode(s).length).padStart(6)}`);
const hex = (n, w) => n.toString(16).padStart(w, '0');
// 4 KB dump: 256 bytes of header then zeros (typical section padding / BSS)
const buf = Buffer.alloc(4096); for (let i = 0; i < 200; i++) buf[i] = (i * 37 + 11) & 0xff;
const lines = []; for (let off = 0; off < buf.length; off += 16) { const r = buf.subarray(off, off + 16); const h = [...r].map(x => hex(x, 2)); lines.push(`${hex(0x400000 + off, 8)}  ${h.slice(0, 8).join(' ')}  ${h.slice(8).join(' ')}  |${[...r].map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join('')}|`); }
const collapsed = []; let prev = null, starred = false;
for (let off = 0, i = 0; off < buf.length; off += 16, i++) { const key = buf.subarray(off, off + 16).toString('hex'); if (key === prev) { if (!starred) { collapsed.push('*'); starred = true; } } else { collapsed.push(lines[i]); starred = false; } prev = key; }
collapsed.push(hex(0x400000 + buf.length, 8));
console.log('=== A. 4 KB dump, 200 bytes data + zero fill ===');
show('full hexdump -C (no * collapsing), 256 lines', lines.join('\n'));
show('hexdump -C default (* collapses repeated lines)', collapsed.join('\n'));
show('run-length note: "00401000-00401fff: 3640 x 00"', lines.slice(0, 13).join('\n') + '\n004000d0-00400fff: 3888 bytes of 00');

console.log('\n=== B. Continuation / truncation hints (fixed cost per response) ===');
show('short hint', '[truncated: lines 1-200 of 1834; next: offset=200]');
show('verbose hint', 'Note: The output has been truncated because it exceeded the maximum response size. Showing lines 1 to 200 out of a total of 1834 lines. To see more of the output, call this tool again with the offset parameter set to 200, or narrow your query using the filter parameter.');
show('cursor-style hint', 'next_cursor: eyJvZmZzZXQiOjIwMCwicSI6IkNyZWF0ZUZpbGUifQ==');
show('offset-style hint', 'next_offset: 200');
show('UUID handle', 'handle: 3f2b9c1e-8a4d-4f6b-9e2a-7c1d5b8e0f3a');
show('short handle', 'handle: d7');
show('typical boilerplate footer', '\n---\n💡 Tip: Use `get_function_xrefs` to see callers, `decompile_function` to view code, or `get_call_graph` for relationships. Results are limited to 100 items; use offset to paginate.');

console.log('\n=== C. Markdown table output as FastMCP structuredContent (JSON-escaped) ===');
const rows = Array.from({ length: 100 }, (_, i) => `| FUN_${hex(0x401000 + i * 0x90, 8)} | 0x${hex(0x401000 + i * 0x90, 8)} | ${(i * 37) % 900 + 8} |`);
const md = ['| Name | Address | Size |', '|---|---|---|', ...rows].join('\n');
show('markdown table text (as content[].text)', md);
show('JSON.stringify({result: md}) (structuredContent-only path)', JSON.stringify({ result: md }));
show('both copies (if a client fed content + structuredContent)', md + JSON.stringify({ result: md }));
