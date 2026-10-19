## 1. Address formats (mean tokens per address over 1,000 random addresses)

| Format | example | o200k | cl100k | claude-legacy | qwen | tekken |
|---|---|---|---|---|---|---|
| 32-bit `0x%08x` | `0x004f8697` | 7.14 | 7.13 | 6.08 | 10.52 | 10.55 |
| 32-bit `%08x` | `004f8697` | 5.14 | 5.13 | 4.67 | 8.52 | 8.55 |
| 32-bit `%08X` | `004F8697` | 5.16 | 5.18 | 4.70 | 8.57 | 8.58 |
| 32-bit `0x%x` | `0x4f8697` | 6.61 | 6.60 | 5.67 | 8.52 | 8.55 |
| 32-bit `%x` | `4f8697` | 4.61 | 4.60 | 3.78 | 6.52 | 6.55 |
| 32-bit decimal | `5211799` | 4.00 | 4.00 | 3.16 | 8.00 | 8.00 |
| Ghidra `FUN_%08x` | `FUN_004f8697` | 6.14 | 6.13 | 7.08 | 9.52 | 10.55 |
| IDA `sub_%X` | `sub_4F8697` | 5.63 | 5.65 | 5.70 | 7.57 | 7.58 |
| RVA `0x%x` (minus 0x400000) | `0xf8697` | 5.75 | 5.75 | 4.76 | 7.10 | 7.23 |
| RVA `%x` (minus 0x400000) | `f8697` | 3.73 | 3.73 | 3.23 | 5.09 | 5.11 |
| 64-bit PE `0x%016x` | `0x000000014001bd38` | 9.58 | 9.57 | 7.11 | 18.64 | 18.68 |
| 64-bit PE `0x%x` | `0x14001bd38` | 7.18 | 7.18 | 6.14 | 11.64 | 11.68 |
| 64-bit PE `%x` | `14001bd38` | 5.18 | 5.18 | 4.33 | 9.64 | 9.68 |
| 64-bit PE RVA `%x` | `1bd38` | 3.81 | 3.80 | 2.92 | 5.25 | 5.28 |
| 64-bit user `0x%016x` | `0x00007ff651aefed8` | 11.35 | 11.35 | 10.46 | 17.14 | 17.21 |
| 64-bit user WinDbg `%08x`%08x` | `00007ff6`51aefed8` | 10.85 | 10.84 | 9.94 | 16.14 | 16.21 |
| 64-bit user `0x%x` | `0x7ff651aefed8` | 10.35 | 10.35 | 9.46 | 13.14 | 13.21 |
| 64-bit user `%x` | `7ff651aefed8` | 8.35 | 8.35 | 7.46 | 11.14 | 11.21 |
| func-relative `+0x%x` (0-0x3ff) | `+0x3cf` | 4.62 | 4.62 | 4.62 | 5.51 | 5.54 |
| func-relative `+%x` (0-0x3ff) | `+3cf` | 2.72 | 2.72 | 2.72 | 3.60 | 3.60 |

PE sample: distlib t64.exe, 108032 bytes, ImageBase=0x140000000, .text VA=0x140001000 size=61440, entry=0x14000427c

## 2. Hexdump formats (tokens per byte; 256-byte samples)


**PE header (file offset 0, 256 B)**

| Format | chars | o200k tok (tok/B) | cl100k tok (tok/B) | claude-legacy tok (tok/B) | qwen tok (tok/B) | tekken tok (tok/B) |
|---|---|---|---|---|---|---|
| xxd (offset + 2-byte groups + ASCII) | 1087 | 578 (2.26) | 580 (2.27) | 444 (1.73) | 849 (3.32) | 860 (3.36) |
| hexdump -C (offset + bytes + |ASCII|) | 1263 | 763 (2.98) | 763 (2.98) | 544 (2.12) | 1008 (3.94) | 1012 (3.95) |
| WinDbg db (backtick addr + bytes + ASCII) | 1359 | 838 (3.27) | 840 (3.28) | 646 (2.52) | 1101 (4.30) | 1112 (4.34) |
| hex bytes spaced, lowercase, 16/line | 767 | 552 (2.16) | 552 (2.16) | 342 (1.34) | 723 (2.82) | 723 (2.82) |
| hex bytes spaced, UPPERCASE, 16/line | 767 | 552 (2.16) | 552 (2.16) | 342 (1.34) | 723 (2.82) | 723 (2.82) |
| hex contiguous, 32 B/line | 519 | 265 (1.04) | 265 (1.04) | 228 (0.89) | 502 (1.96) | 504 (1.97) |
| base64 (one line) | 344 | 171 (0.67) | 185 (0.72) | 174 (0.68) | 189 (0.74) | 227 (0.89) |
| C escapes \xNN | 1024 | 561 (2.19) | 559 (2.18) | 803 (3.14) | 730 (2.85) | 754 (2.95) |
| C array 0xNN,  | 1534 | 1313 (5.13) | 1313 (5.13) | 1058 (4.13) | 1484 (5.80) | 1496 (5.84) |

**.text code at entry (256 B)**

| Format | chars | o200k tok (tok/B) | cl100k tok (tok/B) | claude-legacy tok (tok/B) | qwen tok (tok/B) | tekken tok (tok/B) |
|---|---|---|---|---|---|---|
| xxd (offset + 2-byte groups + ASCII) | 1087 | 617 (2.41) | 619 (2.42) | 512 (2.00) | 908 (3.55) | 914 (3.57) |
| hexdump -C (offset + bytes + |ASCII|) | 1263 | 791 (3.09) | 792 (3.09) | 582 (2.27) | 1065 (4.16) | 1069 (4.18) |
| WinDbg db (backtick addr + bytes + ASCII) | 1359 | 859 (3.36) | 861 (3.36) | 680 (2.66) | 1150 (4.49) | 1156 (4.52) |
| hex bytes spaced, lowercase, 16/line | 767 | 528 (2.06) | 528 (2.06) | 315 (1.23) | 727 (2.84) | 727 (2.84) |
| hex bytes spaced, UPPERCASE, 16/line | 767 | 528 (2.06) | 528 (2.06) | 315 (1.23) | 727 (2.84) | 727 (2.84) |
| hex contiguous, 32 B/line | 519 | 229 (0.89) | 228 (0.89) | 232 (0.91) | 502 (1.96) | 504 (1.97) |
| base64 (one line) | 344 | 211 (0.82) | 229 (0.89) | 217 (0.85) | 229 (0.89) | 247 (0.96) |
| C escapes \xNN | 1024 | 540 (2.11) | 537 (2.10) | 783 (3.06) | 736 (2.88) | 755 (2.95) |
| C array 0xNN,  | 1534 | 1293 (5.05) | 1293 (5.05) | 1038 (4.05) | 1492 (5.83) | 1502 (5.87) |

**.rdata string-rich (256 B)**

| Format | chars | o200k tok (tok/B) | cl100k tok (tok/B) | claude-legacy tok (tok/B) | qwen tok (tok/B) | tekken tok (tok/B) |
|---|---|---|---|---|---|---|
| xxd (offset + 2-byte groups + ASCII) | 1087 | 578 (2.26) | 579 (2.26) | 443 (1.73) | 883 (3.45) | 885 (3.46) |
| hexdump -C (offset + bytes + |ASCII|) | 1263 | 758 (2.96) | 759 (2.96) | 501 (1.96) | 1045 (4.08) | 1046 (4.09) |
| WinDbg db (backtick addr + bytes + ASCII) | 1359 | 836 (3.27) | 837 (3.27) | 598 (2.34) | 1139 (4.45) | 1141 (4.46) |
| hex bytes spaced, lowercase, 16/line | 767 | 555 (2.17) | 555 (2.17) | 315 (1.23) | 767 (3.00) | 767 (3.00) |
| hex bytes spaced, UPPERCASE, 16/line | 767 | 555 (2.17) | 555 (2.17) | 315 (1.23) | 767 (3.00) | 767 (3.00) |
| hex contiguous, 32 B/line | 519 | 221 (0.86) | 221 (0.86) | 246 (0.96) | 519 (2.03) | 519 (2.03) |
| base64 (one line) | 344 | 222 (0.87) | 238 (0.93) | 209 (0.82) | 239 (0.93) | 267 (1.04) |
| C escapes \xNN | 1024 | 556 (2.17) | 556 (2.17) | 812 (3.17) | 768 (3.00) | 768 (3.00) |
| C array 0xNN,  | 1534 | 1322 (5.16) | 1322 (5.16) | 1067 (4.17) | 1534 (5.99) | 1534 (5.99) |

**random/high-entropy (256 B)**

| Format | chars | o200k tok (tok/B) | cl100k tok (tok/B) | claude-legacy tok (tok/B) | qwen tok (tok/B) | tekken tok (tok/B) |
|---|---|---|---|---|---|---|
| xxd (offset + 2-byte groups + ASCII) | 1087 | 645 (2.52) | 651 (2.54) | 586 (2.29) | 843 (3.29) | 847 (3.31) |
| hexdump -C (offset + bytes + |ASCII|) | 1263 | 809 (3.16) | 813 (3.18) | 666 (2.60) | 974 (3.80) | 977 (3.82) |
| WinDbg db (backtick addr + bytes + ASCII) | 1359 | 881 (3.44) | 885 (3.46) | 766 (2.99) | 1062 (4.15) | 1064 (4.16) |
| hex bytes spaced, lowercase, 16/line | 767 | 545 (2.13) | 545 (2.13) | 398 (1.55) | 632 (2.47) | 632 (2.47) |
| hex bytes spaced, UPPERCASE, 16/line | 767 | 545 (2.13) | 545 (2.13) | 398 (1.55) | 632 (2.47) | 632 (2.47) |
| hex contiguous, 32 B/line | 519 | 307 (1.20) | 308 (1.20) | 312 (1.22) | 451 (1.76) | 455 (1.78) |
| base64 (one line) | 344 | 240 (0.94) | 248 (0.97) | 249 (0.97) | 254 (0.99) | 268 (1.05) |
| C escapes \xNN | 1024 | 582 (2.27) | 581 (2.27) | 796 (3.11) | 668 (2.61) | 727 (2.84) |
| C array 0xNN,  | 1534 | 1306 (5.10) | 1306 (5.10) | 1051 (4.11) | 1393 (5.44) | 1435 (5.61) |

**all zero (256 B)**

| Format | chars | o200k tok (tok/B) | cl100k tok (tok/B) | claude-legacy tok (tok/B) | qwen tok (tok/B) | tekken tok (tok/B) |
|---|---|---|---|---|---|---|
| xxd (offset + 2-byte groups + ASCII) | 1087 | 501 (1.96) | 501 (1.96) | 244 (0.95) | 831 (3.25) | 863 (3.37) |
| hexdump -C (offset + bytes + |ASCII|) | 1263 | 662 (2.59) | 662 (2.59) | 404 (1.58) | 992 (3.88) | 992 (3.88) |
| WinDbg db (backtick addr + bytes + ASCII) | 1359 | 741 (2.89) | 741 (2.89) | 515 (2.01) | 1087 (4.25) | 1119 (4.37) |
| hex bytes spaced, lowercase, 16/line | 767 | 511 (2.00) | 511 (2.00) | 271 (1.06) | 767 (3.00) | 767 (3.00) |
| hex bytes spaced, UPPERCASE, 16/line | 767 | 511 (2.00) | 511 (2.00) | 271 (1.06) | 767 (3.00) | 767 (3.00) |
| hex contiguous, 32 B/line | 519 | 183 (0.71) | 183 (0.71) | 23 (0.09) | 519 (2.03) | 519 (2.03) |
| base64 (one line) | 344 | 45 (0.18) | 45 (0.18) | 44 (0.17) | 45 (0.18) | 172 (0.67) |
| C escapes \xNN | 1024 | 512 (2.00) | 512 (2.00) | 768 (3.00) | 768 (3.00) | 768 (3.00) |
| C array 0xNN,  | 1534 | 1278 (4.99) | 1278 (4.99) | 1023 (4.00) | 1534 (5.99) | 1534 (5.99) |

## 3. Mangled vs demangled C++/Rust names (tokens)

| Scheme | mangled | o200k m/d/s | cl100k m/d/s | claude-legacy m/d/s | qwen m/d/s | tekken m/d/s |
|---|---|---|---|---|---|---|
| MSVC | `?GetInstance@CManager@@SAPAV1@XZ` | 12/16/5 | 13/15/4 | 12/18/5 | 13/15/4 | 14/17/5 |
| MSVC | `??0CString@@QAE@PBD@Z` | 11/11/3 | 11/11/3 | 12/14/5 | 11/11/3 | 12/13/5 |
| MSVC | `?push_back@?$vector@HV?$allocator@H@std@@@std@@QEAAXAEBH@Z` | 26/28/7 | 26/28/7 | 29/36/9 | 26/30/7 | 29/34/7 |
| MSVC | `??_7type_info@@6B@` | 9/9/6 | 9/9/6 | 10/10/7 | 9/9/6 | 9/9/6 |
| MSVC | `?_Xlength_error@std@@YAXPEBD@Z` | 13/15/5 | 14/15/5 | 14/19/7 | 14/16/5 | 13/17/5 |
| Itanium | `_ZNSt6vectorIiSaIiEE9push_backERKi` | 14/16/7 | 16/16/7 | 17/23/9 | 16/16/7 | 16/19/7 |
| Itanium | `_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv` | 25/26/6 | 27/25/6 | 29/34/7 | 30/26/6 | 31/29/6 |
| Itanium | `_ZSt4cout` | 4/3/3 | 4/3/3 | 5/3/3 | 4/3/3 | 4/3/3 |
| Rust legacy | `_ZN4core3fmt5write17h0f5ecb6c3e3a5d9bE` | 26/22/5 | 26/22/5 | 27/22/5 | 27/22/5 | 27/22/5 |
| **total** | | 140/146/47 | 146/144/46 | 155/179/57 | 150/148/46 | 155/163/49 |

(m = mangled, d = full demangled (undname / c++filt style), s = simplified `Namespace::Function` form)

## 4. Ghidra pseudocode normalization on 656 real Ghidra outputs (LLM4Decompile HumanEval-Decompile, gcc x86-64 O0-O3)

| Transform | chars | o200k tokens (Δ vs raw) | cl100k tokens (Δ vs raw) | claude-legacy tokens (Δ vs raw) | qwen tokens (Δ vs raw) | tekken tokens (Δ vs raw) |
|---|---|---|---|---|---|---|
| raw Ghidra output | 722,843 | 288,290 | 282,727 | 288,359 | 300,412 | 311,985 |
| W1 drop blank lines + trailing ws | 720,244 | 287,653 (-0.2%) | 282,090 (-0.2%) | 287,671 (-0.2%) | 299,775 (-0.2%) | 310,711 (-0.4%) |
| W2 W1 + collapse internal space runs (ida-pro-mcp PR#341 rule) | 720,185 | 287,594 (-0.2%) | 282,031 (-0.2%) | 287,612 (-0.3%) | 299,716 (-0.2%) | 310,652 (-0.4%) |
| W3 W2 + indent 1 space/level (Ghidra uses 2) | 652,792 | 277,552 (-3.7%) | 271,989 (-3.8%) | 287,612 (-0.3%) | 289,674 (-3.6%) | 300,610 (-3.6%) |
| W3t W2 + indent 1 tab/level | 652,792 | 285,968 (-0.8%) | 280,397 (-0.8%) | 313,325 (+8.7%) | 298,082 (-0.8%) | 310,245 (-0.6%) |
| W4 W2 + no indentation | 585,689 | 261,508 (-9.3%) | 255,983 (-9.5%) | 287,374 (-0.3%) | 273,668 (-8.9%) | 284,800 (-8.7%) |
| C  strip comments only | 718,619 | 287,346 (-0.3%) | 281,767 (-0.3%) | 287,398 (-0.3%) | 299,452 (-0.3%) | 311,137 (-0.3%) |
| N1 strip zero-padding in FUN_/DAT_/LAB_ only | 720,933 | 287,604 (-0.2%) | 282,041 (-0.2%) | 287,997 (-0.1%) | 298,502 (-0.6%) | 310,075 (-0.6%) |
| N2 short auto-names only (param_N->aN, local_x/xVarN->vN) | 577,468 | 249,878 (-13.3%) | 249,083 (-11.9%) | 250,006 (-13.3%) | 263,496 (-12.3%) | 270,966 (-13.1%) |
| N3 short symbol prefixes (FUN_->f_, DAT_->d_, LAB_->L_) + N1 | 719,297 | 287,599 (-0.2%) | 282,036 (-0.2%) | 287,997 (-0.1%) | 298,497 (-0.6%) | 309,580 (-0.8%) |
| T  undefinedN/ulong/uint... -> u64/u32/... only | 709,548 | 290,909 (+0.9%) | 285,346 (+0.9%) | 290,742 (+0.8%) | 305,526 (+1.7%) | 316,234 (+1.4%) |
| K  strip casts only (LOSSY) | 676,743 | 273,586 (-5.1%) | 267,321 (-5.4%) | 270,890 (-6.1%) | 285,006 (-5.1%) | 295,255 (-5.4%) |
| COMBO-lossless: W3 + C + N1 + N2 | 501,283 | 237,510 (-17.6%) | 236,699 (-16.3%) | 247,953 (-14.0%) | 249,888 (-16.8%) | 256,833 (-17.7%) |
| COMBO-lossless+: W4 + C + N1 + N2 + N3 | 432,544 | 221,088 (-23.3%) | 220,245 (-22.1%) | 247,764 (-14.1%) | 233,434 (-22.3%) | 240,056 (-23.1%) |
| COMBO-aggressive: COMBO-lossless+ + T + K | 378,750 | 208,882 (-27.5%) | 208,610 (-26.2%) | 231,568 (-19.7%) | 223,018 (-25.8%) | 225,197 (-27.8%) |

Token-class share in raw Ghidra output (whitespace-only tokens, pure-parenthesis tokens):

| tokenizer | total | whitespace-only | % | parenthesis-only | % |
|---|---|---|---|---|---|
| o200k | 288,290 | 36,433 | 12.6% | 17,263 | 6.0% |
| cl100k | 282,727 | 36,428 | 12.9% | 17,585 | 6.2% |
| claude-legacy | 288,359 | 28,248 | 9.8% | 21,415 | 7.4% |
| qwen | 300,412 | 36,428 | 12.1% | 17,585 | 5.9% |
| tekken | 311,985 | 37,097 | 11.9% | 19,053 | 6.1% |

Ghidra pseudocode vs original C source, and signature line vs whole function (o200k tokens):

| opt | n | source tok (mean) | Ghidra raw tok (mean) | ratio raw/src | COMBO-lossless+ (mean) | ratio/src | signature line tok (mean) | max raw tok |
|---|---|---|---|---|---|---|---|---|
| O0 | 164 | 139 | 320 | 2.30 | 246 | 1.77 | 13.7 | 1910 |
| O1 | 164 | 139 | 395 | 2.84 | 300 | 2.16 | 14.1 | 2671 |
| O2 | 164 | 139 | 380 | 2.73 | 290 | 2.08 | 14.2 | 1634 |
| O3 | 164 | 139 | 663 | 4.77 | 512 | 3.68 | 14.3 | 8886 |

Example (O2) raw:
```c
undefined8 func0(float param_1,long param_2,int param_3)

{
  long lVar1;
  long lVar2;
  long lVar3;
  
  if (0 < param_3) {
    lVar3 = 1;
    lVar2 = (ulong)(param_3 - 1) + 1;
    if (lVar2 != 1) {
      do {
        lVar1 = lVar3;
        do {
          if ((float)((uint)(*(float *)(param_2 + -4 + lVar3 * 4) - *(float *)(param_2 + lVar1 * 4))
                     & DAT_001020b0) < param_1) {
            return 1;
          }
          lVar1 = lVar1 + 1;
        } while ((int)lVar1 < param_3);
        lVar3 = lVar3 + 1;
      } while (lVar3 != lVar2);
    }
  }
  return 0;
}
```
Example COMBO-lossless+:
```c
undefined8 func0(float a1,long a2,int a3)
{
long v0;
long v1;
long v2;
if (0 < a3) {
v2 = 1;
v1 = (ulong)(a3 - 1) + 1;
if (v1 != 1) {
do {
v0 = v2;
do {
if ((float)((uint)(*(float *)(a2 + -4 + v2 * 4) - *(float *)(a2 + v0 * 4))
& d_1020b0) < a1) {
return 1;
}
v0 = v0 + 1;
} while ((int)v0 < a3);
v2 = v2 + 1;
} while (v2 != v1);
}
}
return 0;
}
```

## 5. Disassembly listing formats (200 real x86-64 instructions from t64.exe entry point, capstone 5.0.7)

| Format | chars | o200k (tok/insn) | cl100k (tok/insn) | claude-legacy (tok/insn) | qwen (tok/insn) | tekken (tok/insn) |
|---|---|---|---|---|---|---|
| x64dbg-like `ADDR16 | BYTES | insn` | 13350 | 5606 (28.0, +0%) | 5559 (27.8, +0%) | 4697 (23.5, +0%) | 8336 (41.7, +0%) | 8440 (42.2, +0%) |
| Ghidra-like `addr bytes MNEMONIC OPS` (padded, uppercase) | 11746 | 4981 (24.9, -11%) | 4956 (24.8, -11%) | 4422 (22.1, -6%) | 6812 (34.1, -18%) | 6977 (34.9, -17%) |
| objdump-like `addr:\tbytes\tinsn` | 11739 | 5585 (27.9, -0%) | 5529 (27.6, -1%) | 4873 (24.4, +4%) | 7385 (36.9, -11%) | 7497 (37.5, -11%) |
| no bytes, `0x%016x  insn` | 8138 | 3944 (19.7, -30%) | 3897 (19.5, -30%) | 3685 (18.4, -22%) | 6166 (30.8, -26%) | 6270 (31.4, -26%) |
| no bytes, `%x insn` | 6138 | 2865 (14.3, -49%) | 2818 (14.1, -49%) | 2885 (14.4, -39%) | 4166 (20.8, -50%) | 4270 (21.4, -49%) |
| no bytes, RVA `%x insn` (+ RVA operands) | 4928 | 2473 (12.4, -56%) | 2426 (12.1, -56%) | 2427 (12.1, -48%) | 2952 (14.8, -65%) | 3059 (15.3, -64%) |
| no bytes, func-relative `+%x insn` | 5087 | 2648 (13.2, -53%) | 2599 (13.0, -53%) | 2620 (13.1, -44%) | 3104 (15.5, -63%) | 3209 (16.0, -62%) |
| no addresses, labels for branch targets | 3993 | 2031 (10.2, -64%) | 1980 (9.9, -64%) | 2020 (10.1, -57%) | 2204 (11.0, -74%) | 2297 (11.5, -73%) |
| `%x insn`, compact operands (drop ` ptr`, spaces) | 5538 | 2599 (13.0, -54%) | 2576 (12.9, -54%) | 2769 (13.8, -41%) | 3924 (19.6, -53%) | 3992 (20.0, -53%) |
| `%x INSN` uppercase mnemonic+regs | 6138 | 2944 (14.7, -47%) | 2919 (14.6, -47%) | 3035 (15.2, -35%) | 4267 (21.3, -49%) | 4431 (22.2, -48%) |

First 3 lines of first and last-but-one formats:
```
000000014000427C | 48 83 EC 28              | sub rsp, 0x28
0000000140004280 | E8 8B 6C 00 00           | call 0x14000af10
0000000140004285 | 48 83 C4 28              | add rsp, 0x28
...
14000427c sub rsp,0x28
140004280 call 0x14000af10
140004285 add rsp,0x28
```

### 6. Import listing formats (t64.exe: 86 imports from 2 DLLs)

| Format | chars | o200k | cl100k | claude-legacy | qwen | tekken |
|---|---|---|---|---|---|---|
| table lines `0x%016x  DLL  name` | 4400 | 1611 | 1507 | 1615 | 2423 | 2630 |
| Markdown table `| addr | dll | name |` | 4870 | 1798 (+12%) | 1694 (+12%) | 1799 (+11%) | 2610 (+8%) | 2817 (+7%) |
| JSON list, indent=2 | 8872 | 3246 (+101%) | 3144 (+109%) | 3159 (+96%) | 4060 (+68%) | 4345 (+65%) |
| JSON list, compact separators | 6807 | 2129 (+32%) | 2027 (+35%) | 2125 (+32%) | 2943 (+21%) | 3313 (+26%) |
| `DLL!name` per line (no addresses) | 2505 | 808 (-50%) | 706 (-53%) | 893 (-45%) | 789 (-67%) | 988 (-62%) |
| grouped by DLL `DLL (n): a, b, c` | 1510 | 394 (-76%) | 370 (-75%) | 401 (-75%) | 372 (-85%) | 415 (-84%) |
| grouped by DLL, lowercase dll w/o .dll | 1409 | 303 (-81%) | 279 (-81%) | 308 (-81%) | 280 (-88%) | 322 (-88%) |

## 7. String listing (t64.exe, ASCII + UTF-16LE)

| Filter | #strings | o200k tokens, `0x%016x: "s"` | o200k tokens, `%x s` (RVA) | o200k tokens, values only |
|---|---|---|---|---|
| min 4 | 1406 | 21,541 | 10,499 | 6,688 |
| min 4, dedupe | 865 | 13,430 | 6,644 | 4,334 |
| min 6, dedupe | 371 | 6,204 | 3,326 | 2,293 |
| min 8, dedupe | 286 | 4,935 | 2,719 | 1,906 |
| min 4, dedupe, 'wordy' filter (>=85% alnum, has 3-letter run) | 304 | 4,873 | 2,520 | 1,676 |
| min 6, dedupe, 'wordy' filter (>=85% alnum, has 3-letter run) | 267 | 4,366 | 2,303 | 1,556 |

### 8. Call-graph formats (t64.exe direct calls: 688 unique edges, 173 caller functions)

| Format | chars | o200k | cl100k | claude-legacy | qwen | tekken |
|---|---|---|---|---|---|---|
| edge list `FUN_x -> FUN_y` | 21327 | 9710 | 9705 | 11290 | 16185 | 17597 |
| Markdown xref table `| from | to | type |` | 25490 | 13165 (+36%) | 13160 (+36%) | 12678 (+12%) | 19640 (+21%) | 19676 (+12%) |
| JSON edges, indent=2 | 55042 | 24161 (+149%) | 24156 (+149%) | 24366 (+116%) | 30636 (+89%) | 30672 (+74%) |
| JSON edges, compact | 38529 | 15218 (+57%) | 15213 (+57%) | 16108 (+43%) | 21693 (+34%) | 22416 (+27%) |
| Mermaid `A --> B` | 23400 | 10401 (+7%) | 10396 (+7%) | 11293 (+0%) | 16876 (+4%) | 18288 (+4%) |
| DOT `"A" -> "B";` | 26157 | 12468 (+28%) | 12463 (+28%) | 14049 (+24%) | 18943 (+17%) | 20355 (+16%) |
| adjacency `FUN_x: FUN_y, FUN_z` | 12741 | 6061 (-38%) | 6058 (-38%) | 7040 (-38%) | 10141 (-37%) | 11015 (-37%) |
| adjacency, RVA hex `x: y z` | 4477 | 3184 (-67%) | 3183 (-67%) | 2628 (-77%) | 4168 (-74%) | 4179 (-76%) |
| JSON adjacency compact `{"x":[y,z]}` RVA | 6374 | 3307 (-66%) | 3131 (-68%) | 3118 (-72%) | 4116 (-75%) | 4475 (-75%) |

### 9. Register-view formats (18 x64 registers, synthetic but realistic values)

| Format | chars | o200k | cl100k | claude-legacy | qwen | tekken |
|---|---|---|---|---|---|---|
| WinDbg `r` style | 492 | 226 | 227 | 164 | 410 | 410 |
| JSON indent=2, `0x%016x` | 561 | 281 (+24%) | 281 (+24%) | 220 (+34%) | 449 (+10%) | 449 (+10%) |
| JSON compact, `0x%x` | 269 | 153 (-32%) | 153 (-33%) | 153 (-7%) | 175 (-57%) | 175 (-57%) |
| text `k=%x` one line | 159 | 98 (-57%) | 98 (-57%) | 98 (-40%) | 120 (-71%) | 120 (-71%) |
| text `k=%x`, zero registers omitted (+ 'others=0') | 117 | 68 (-70%) | 68 (-70%) | 68 (-59%) | 85 (-79%) | 85 (-79%) |
