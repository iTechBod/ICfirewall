import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests

WORKSPACE_ROOT = Path(os.getenv("AGENT_WORKSPACE_ROOT", os.getcwd())).expanduser().resolve()
SEARXNG_URL = os.getenv("SEARXNG_URL", "").rstrip("/")
ALLOW_FILE_DELETE = os.getenv("ALLOW_FILE_DELETE", "false").lower() == "true"
ALLOW_BASH = os.getenv("ALLOW_BASH", "false").lower() == "true"
MAX_READ_BYTES = 200_000


def _safe_path(relative_path: str) -> Path:
    candidate = (WORKSPACE_ROOT / relative_path).resolve()
    if candidate != WORKSPACE_ROOT and WORKSPACE_ROOT not in candidate.parents:
        raise ValueError("path is outside the allowed workspace")
    return candidate


def read_file(relative_path: str) -> str:
    path = _safe_path(relative_path)
    if not path.is_file():
        raise ValueError("file does not exist")
    if path.stat().st_size > MAX_READ_BYTES:
        raise ValueError("file is larger than the read limit")
    return path.read_text(encoding="utf-8")


def write_file(relative_path: str, content: str) -> str:
    path = _safe_path(relative_path)
    if path.exists() and path.is_symlink():
        raise ValueError("refusing to write through a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return f"wrote {path.relative_to(WORKSPACE_ROOT)}"


def delete_file(relative_path: str) -> str:
    if not ALLOW_FILE_DELETE:
        raise PermissionError("file deletion is disabled; set ALLOW_FILE_DELETE=true to enable it")
    path = _safe_path(relative_path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("only regular files inside the workspace may be deleted")
    path.unlink()
    return f"deleted {path.relative_to(WORKSPACE_ROOT)}"


def rename_file(relative_path: str, new_relative_path: str) -> str:
    source = _safe_path(relative_path)
    target = _safe_path(new_relative_path)
    if not source.is_file() or source.is_symlink() or target.exists():
        raise ValueError("rename requires a regular source file and a new unused target")
    target.parent.mkdir(parents=True, exist_ok=True)
    source.rename(target)
    return f"renamed {source.relative_to(WORKSPACE_ROOT)} to {target.relative_to(WORKSPACE_ROOT)}"


def run_bash(command: str) -> str:
    if not ALLOW_BASH:
        raise PermissionError("bash is disabled; set ALLOW_BASH=true to enable it")
    result = subprocess.run(command, shell=True, cwd=WORKSPACE_ROOT, capture_output=True, text=True, timeout=30)
    output = (result.stdout + result.stderr)[-MAX_READ_BYTES:]
    return f"exit={result.returncode}\n{output}"


def search_files(query: str, path: str = ".") -> str:
    search_root = _safe_path(path)
    if not search_root.exists():
        raise ValueError("search path does not exist")
    result = subprocess.run(
        ["rg", "--line-number", "--hidden", "--glob", "!.dfx", "--glob", "!.backups", query, str(search_root)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result.stdout[:MAX_READ_BYTES] or "No matches."


def web_search(query: str) -> str:
    if not SEARXNG_URL:
        raise RuntimeError("SEARXNG_URL is not configured")
    parsed = urlparse(SEARXNG_URL)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("SEARXNG_URL must be an http or https URL")
    response = requests.get(
        f"{SEARXNG_URL}/search",
        params={"q": query, "format": "json", "language": "all"},
        timeout=15,
    )
    response.raise_for_status()
    results = response.json().get("results", [])[:5]
    return json.dumps([
        {"title": item.get("title"), "url": item.get("url"), "snippet": item.get("content", "")}
        for item in results
    ])


TOOL_DEFINITIONS = [
    {"type": "function", "function": {"name": "read_file", "description": "Read a UTF-8 file inside the allowed workspace.", "parameters": {"type": "object", "properties": {"relative_path": {"type": "string"}}, "required": ["relative_path"]}}},
    {"type": "function", "function": {"name": "write_file", "description": "Write a UTF-8 file inside the allowed workspace. Never write outside it.", "parameters": {"type": "object", "properties": {"relative_path": {"type": "string"}, "content": {"type": "string"}}, "required": ["relative_path", "content"]}}},
    {"type": "function", "function": {"name": "delete_file", "description": "Delete a regular file inside the allowed workspace. This is disabled unless explicitly enabled.", "parameters": {"type": "object", "properties": {"relative_path": {"type": "string"}}, "required": ["relative_path"]}}},
    {"type": "function", "function": {"name": "rename_file", "description": "Rename a regular file inside the allowed workspace.", "parameters": {"type": "object", "properties": {"relative_path": {"type": "string"}, "new_relative_path": {"type": "string"}}, "required": ["relative_path", "new_relative_path"]}}},
    {"type": "function", "function": {"name": "run_bash", "description": "Run a shell command in the allowed workspace. Disabled unless explicitly enabled.", "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {"name": "search_files", "description": "Search workspace text files with ripgrep.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}, "path": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "web_search", "description": "Search the configured private SearXNG instance.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
]

TOOL_FUNCTIONS = {"read_file": read_file, "write_file": write_file, "delete_file": delete_file, "rename_file": rename_file, "run_bash": run_bash, "search_files": search_files, "web_search": web_search}


def run_tool(name: str, arguments: dict) -> str:
    if name not in TOOL_FUNCTIONS:
        return f"tool error: unknown tool {name}"
    try:
        return str(TOOL_FUNCTIONS[name](**arguments))
    except Exception as error:
        return f"tool error: {type(error).__name__}: {error}"
