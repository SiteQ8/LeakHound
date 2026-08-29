"""The scanning engine.

Walks files or directories (and optionally git history), applies the rules,
and returns a list of Finding objects.
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterable, List, Tuple

from .entropy import shannon_entropy
from .findings import Finding
from .rules import DEFAULT_RULES, GENERIC_ENTROPY_RULE, Rule

# Directories that are noise almost everywhere.
DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "dist", "build",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".idea", ".vscode", "vendor", "target", ".next", ".cache",
}

# File extensions that are binary or otherwise not worth reading as text.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".class", ".o", ".a",
    ".pyc", ".pyo", ".jar", ".wasm", ".lock",
}

MAX_FILE_BYTES = 5 * 1024 * 1024   # skip files larger than this

# Comment markers that suppress findings on a line.
ALLOW_MARKERS = ("leakhound:allow", "leakhound-disable-line", "pragma: allowlist secret")

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")

_PLACEHOLDER_HINTS = (
    "example", "changeme", "change_me", "placeholder", "your_", "your-",
    "xxxxxx", "dummy", "redacted", "sample", "test1234", "password123",
    "notreal", "fake", "<", ">", "{{", "}}", "...", "****",
)


@dataclass
class Config:
    paths: List[str] = field(default_factory=lambda: ["."])
    rules: List[Rule] = field(default_factory=lambda: list(DEFAULT_RULES))
    use_entropy: bool = True
    entropy_threshold: float = 4.3
    min_token_len: int = 20
    excludes: List[str] = field(default_factory=list)
    scan_git_history: bool = False


def is_placeholder(value: str) -> bool:
    v = value.lower()
    if any(h in v for h in _PLACEHOLDER_HINTS):
        return True
    if len(set(value)) <= 2:
        return True
    return False


def _overlaps(start: int, end: int, spans: Iterable[Tuple[int, int]]) -> bool:
    return any(not (end <= cs or start >= ce) for cs, ce in spans)


def _extract_tokens(line: str, min_len: int):
    for m in _TOKEN_RE.finditer(line):
        tok = m.group(0)
        if len(tok) >= min_len:
            yield tok, m.start(), m.end()


def scan_line(line: str, cfg: Config) -> List[Tuple[Rule, str, int]]:
    """Return a list of (rule, secret, column) matches for one line."""
    out: List[Tuple[Rule, str, int]] = []
    claimed: List[Tuple[int, int]] = []

    for rule in cfg.rules:
        for m in rule.pattern.finditer(line):
            group = rule.group if rule.group else 0
            secret = m.group(group) if m.lastindex is not None or group == 0 else m.group(0)
            if not secret:
                continue
            if rule.min_entropy:
                if shannon_entropy(secret) < rule.min_entropy:
                    continue
                if is_placeholder(secret):
                    continue
            start, end = m.span(group)
            out.append((rule, secret, start))
            claimed.append((start, end))

    if cfg.use_entropy:
        for tok, s, e in _extract_tokens(line, cfg.min_token_len):
            if _overlaps(s, e, claimed):
                continue
            if shannon_entropy(tok) >= cfg.entropy_threshold and not is_placeholder(tok):
                out.append((GENERIC_ENTROPY_RULE, tok, s))
                claimed.append((s, e))

    return out


def scan_text(path: str, text: str, cfg: Config, source: str = "worktree", blob: str = "") -> List[Finding]:
    findings: List[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if any(marker in line for marker in ALLOW_MARKERS):
            continue
        for rule, secret, col in scan_line(line, cfg):
            findings.append(Finding(
                rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
                path=path, line=lineno, column=col + 1, secret=secret,
                source=source, blob=blob,
            ))
    return findings


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096]


def scan_file(path: str, cfg: Config) -> List[Finding]:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return []
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return []
        with open(path, "rb") as fh:
            raw = fh.read()
    except (OSError, ValueError):
        return []
    if _looks_binary(raw):
        return []
    text = raw.decode("utf-8", errors="replace")
    return scan_text(path, text, cfg, source="worktree")


def _is_excluded(rel: str, patterns: List[str]) -> bool:
    rel = rel.replace(os.sep, "/")
    base = os.path.basename(rel)
    for pat in patterns:
        p = pat.strip().rstrip("/")
        if not p:
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(base, p):
            return True
        if rel == p or rel.startswith(p + "/"):
            return True
    return False


def load_ignore_file(root: str) -> List[str]:
    """Read patterns from a .leakhoundignore file at the given root."""
    patterns: List[str] = []
    ignore_path = os.path.join(root, ".leakhoundignore")
    if os.path.isfile(ignore_path):
        with open(ignore_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                s = raw.strip()
                if s and not s.startswith("#"):
                    patterns.append(s)
    return patterns


def iter_files(paths: List[str], excludes: List[str]):
    for base in paths:
        if os.path.isfile(base):
            yield base
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
            for name in filenames:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, base)
                if _is_excluded(rel, excludes):
                    continue
                yield full


def scan_paths(cfg: Config) -> List[Finding]:
    """Scan the configured paths on disk and return findings."""
    excludes = list(cfg.excludes)
    for base in cfg.paths:
        root = base if os.path.isdir(base) else os.path.dirname(base) or "."
        excludes += load_ignore_file(root)

    findings: List[Finding] = []
    for path in iter_files(cfg.paths, excludes):
        findings.extend(scan_file(path, cfg))
    return findings


def _git(root: str, args: List[str]) -> Tuple[int, bytes]:
    try:
        proc = subprocess.run(
            ["git", "-C", root] + args,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        return 127, b""


def scan_git_history(root: str, cfg: Config) -> List[Finding]:
    """Scan every unique blob in the repository history once."""
    code, _ = _git(root, ["rev-parse", "--is-inside-work-tree"])
    if code != 0:
        return []

    code, out = _git(root, ["rev-list", "--objects", "--all"])
    if code != 0:
        return []

    seen = set()
    blobs: List[Tuple[str, str]] = []
    for raw in out.decode("utf-8", "replace").splitlines():
        parts = raw.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, path = parts[0], parts[1]
        if sha in seen or not path:
            continue
        seen.add(sha)
        blobs.append((sha, path))

    findings: List[Finding] = []
    for sha, path in blobs:
        ext = os.path.splitext(path)[1].lower()
        if ext in BINARY_EXTENSIONS:
            continue
        code, content = _git(root, ["cat-file", "-p", sha])
        if code != 0 or not content or _looks_binary(content) or len(content) > MAX_FILE_BYTES:
            continue
        text = content.decode("utf-8", "replace")
        findings.extend(scan_text(path, text, cfg, source="history", blob=sha[:12]))
    return findings
