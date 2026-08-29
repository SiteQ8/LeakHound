"""Output formatters for findings: text, json, and SARIF."""
from __future__ import annotations

import json
from typing import Dict, List

from .findings import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_COLORS = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[31m",        # red
    "medium": "\033[33m",      # yellow
    "low": "\033[36m",         # cyan
    "reset": "\033[0m",
    "dim": "\033[2m",
    "green": "\033[32m",
    "bold": "\033[1m",
}


def _c(key: str, use_color: bool) -> str:
    return _COLORS[key] if use_color else ""


def _sort_key(f: Finding):
    return (f.source, f.path, f.line, f.column)


def format_text(findings: List[Finding], use_color: bool = False) -> str:
    reset = _c("reset", use_color)
    if not findings:
        return f"{_c('green', use_color)}No secrets found. You are clear.{reset}"

    lines: List[str] = []
    ordered = sorted(findings, key=_sort_key)
    current = None
    for f in ordered:
        header = f.path + (f"  {_c('dim', use_color)}(history {f.blob}){reset}" if f.source == "history" else "")
        if header != current:
            lines.append("")
            lines.append(f"{_c('bold', use_color)}{header}{reset}")
            current = header
        sev = f"{_c(f.severity, use_color)}{f.severity.upper():<8}{reset}"
        loc = f"{_c('dim', use_color)}{f.line}:{f.column}{reset}"
        lines.append(f"  {loc}  {sev}  {f.rule_name}  {_c('dim', use_color)}{f.masked()}{reset}")

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    files = len({(f.source, f.path) for f in findings})
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts.get(s)]
    summary = ", ".join(parts) if parts else "0"
    lines.append("")
    lines.append(f"{_c('bold', use_color)}{len(findings)} finding(s){reset} across {files} file(s): {summary}")
    return "\n".join(lines).lstrip("\n")


def format_json(findings: List[Finding], version: str) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    payload = {
        "tool": "leakhound",
        "version": version,
        "summary": {
            "total": len(findings),
            "files": len({(f.source, f.path) for f in findings}),
            "by_severity": counts,
        },
        "findings": [f.to_dict() for f in sorted(findings, key=_sort_key)],
    }
    return json.dumps(payload, indent=2)


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def format_sarif(findings: List[Finding], version: str) -> str:
    from .rules import RULES_BY_ID

    used_rule_ids = {f.rule_id for f in findings}
    sarif_rules = []
    for rid in sorted(used_rule_ids):
        rule = RULES_BY_ID.get(rid)
        if not rule:
            continue
        sarif_rules.append({
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _sarif_level(rule.severity)},
        })

    results = []
    for f in sorted(findings, key=_sort_key):
        results.append({
            "ruleId": f.rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f"{f.rule_name} detected ({f.masked()})."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }],
            "partialFingerprints": {"leakhound/v1": f.fingerprint()},
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LeakHound",
                "informationUri": "https://github.com/SiteQ8/LeakHound",
                "version": version,
                "rules": sarif_rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
