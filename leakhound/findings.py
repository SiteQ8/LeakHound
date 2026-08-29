"""The Finding type plus helpers for masking and fingerprinting secrets."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


def mask_secret(secret: str) -> str:
    """Return a redacted view that keeps a short prefix and suffix only."""
    n = len(secret)
    if n <= 6:
        return "*" * max(n, 3)
    front, back = 4, 2
    stars = min(n - front - back, 24)
    return secret[:front] + "*" * stars + secret[-back:]


def fingerprint(rule_id: str, secret: str) -> str:
    """A stable short id for a finding, handy for allowlisting and dedup."""
    digest = hashlib.sha1(f"{rule_id}:{secret}".encode("utf-8", "replace"))
    return digest.hexdigest()[:12]


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str          # critical | high | medium | low
    path: str
    line: int
    column: int
    secret: str
    source: str = "worktree"   # worktree | history
    blob: str = ""

    def masked(self) -> str:
        return mask_secret(self.secret)

    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, self.secret)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "match": self.masked(),
            "fingerprint": self.fingerprint(),
            "source": self.source,
            "blob": self.blob,
        }
