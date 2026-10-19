"""Shared setup for the binary-mcp token audit (read-only against the repo).

Every write the server might do is redirected into the scratchpad via env vars
(HOME, BINARY_CACHE_DIR, BINARY_MCP_SESSION_DIR, XDG_CACHE_HOME) and cwd.
"""
import os
import sys

SP = "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad"
REPO = "/home/user/binary-mcp"
TOK_DIR = f"{SP}/pylib_litellm/litellm/litellm_core_utils/tokenizers"
os.environ["TIKTOKEN_CACHE_DIR"] = TOK_DIR
if f"{SP}/pylib" not in sys.path:
    sys.path.append(f"{SP}/pylib")


def setup_env(extra=None):
    env = {
        "HOME": f"{SP}/home",
        "BINARY_CACHE_DIR": f"{SP}/cache",
        "BINARY_MCP_SESSION_DIR": f"{SP}/sessions",
        "XDG_CACHE_HOME": f"{SP}/xdg_cache",
        "BINARY_MCP_ALLOWED_DIRS": f"{SP}/pe_samples{os.pathsep}{REPO}/samples",
        "TIKTOKEN_CACHE_DIR": TOK_DIR,
        "BINARY_MCP_LOG_LEVEL": "ERROR",
        "BINARY_MCP_AUTO_PDB": "0",
    }
    if extra:
        env.update(extra)
    for k, v in env.items():
        os.environ[k] = v
    for d in ("home", "cache", "sessions", "xdg_cache"):
        os.makedirs(f"{SP}/{d}", exist_ok=True)
    os.chdir(SP)
    if REPO not in sys.path:
        sys.path.insert(0, REPO)
    if f"{SP}/pylib" not in sys.path:
        sys.path.append(f"{SP}/pylib")


_ENC = {}


def _enc(name):
    if name not in _ENC:
        import tiktoken
        _ENC[name] = tiktoken.get_encoding(name)
    return _ENC[name]


_LEGACY = None


def _legacy():
    global _LEGACY
    if _LEGACY is None:
        try:
            from tokenizers import Tokenizer
            _LEGACY = Tokenizer.from_file(f"{TOK_DIR}/anthropic_tokenizer.json")
        except Exception:  # tokenizers not installed
            _LEGACY = False
    return _LEGACY


def count(text: str) -> dict:
    """Token counts for one string under several tokenizers."""
    out = {
        "bytes": len(text.encode("utf-8")),
        "chars": len(text),
        "chars_div4": round(len(text) / 4),
        "o200k": len(_enc("o200k_base").encode(text, disallowed_special=())),
        "cl100k": len(_enc("cl100k_base").encode(text, disallowed_special=())),
    }
    lg = _legacy()
    if lg:
        out["claude_legacy"] = len(lg.encode(text).ids)
    return out


def jdump(obj) -> str:
    """Compact JSON as pydantic's model_dump_json emits it (no spaces)."""
    import json
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
