"""LeakHound: a zero dependency scanner that catches leaked secrets.

Public entry points:
    from leakhound import scan_paths, __version__
"""
from __future__ import annotations

__version__ = "0.1.0"

from .scanner import Config, scan_paths, scan_git_history  # noqa: E402
from .findings import Finding  # noqa: E402

__all__ = ["__version__", "Config", "scan_paths", "scan_git_history", "Finding"]
