"""The detection rules.

Each rule pairs a compiled pattern with a severity and a short description.
Rules with a positive min_entropy are heuristic: a match is only reported when
the captured value looks random enough and is not an obvious placeholder.
Specific format rules leave min_entropy at zero and always report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str            # critical | high | medium | low
    description: str
    pattern: "re.Pattern"
    group: int = 0           # which capture group holds the secret
    min_entropy: float = 0.0


def _c(pattern: str) -> "re.Pattern":
    return re.compile(pattern)


DEFAULT_RULES = [
    Rule("private_key", "Private key", "critical",
         "A PEM private key block header.",
         _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),

    Rule("aws_access_key_id", "AWS access key id", "high",
         "An AWS access key id.",
         _c(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b"), 1),

    Rule("aws_secret_access_key", "AWS secret access key", "critical",
         "An AWS secret access key assigned to a known variable.",
         _c(r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), 1),

    Rule("github_pat", "GitHub personal access token", "high",
         "A classic GitHub personal access token.",
         _c(r"\bghp_[0-9A-Za-z]{36}\b")),

    Rule("github_fine_grained", "GitHub fine grained token", "high",
         "A fine grained GitHub token.",
         _c(r"\bgithub_pat_[0-9A-Za-z_]{82}\b")),

    Rule("github_oauth", "GitHub OAuth token", "high",
         "A GitHub OAuth access token.",
         _c(r"\bgho_[0-9A-Za-z]{36}\b")),

    Rule("github_server_token", "GitHub app or refresh token", "high",
         "A GitHub app or refresh token.",
         _c(r"\b(?:ghu|ghs|ghr)_[0-9A-Za-z]{36}\b")),

    Rule("google_api_key", "Google API key", "high",
         "A Google API key.",
         _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),

    Rule("slack_token", "Slack token", "high",
         "A Slack API token.",
         _c(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),

    Rule("slack_webhook", "Slack webhook", "medium",
         "A Slack incoming webhook url.",
         _c(r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+")),

    Rule("stripe_secret_key", "Stripe secret key", "high",
         "A live Stripe secret or restricted key.",
         _c(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24}\b")),

    Rule("sendgrid_key", "SendGrid API key", "high",
         "A SendGrid API key.",
         _c(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b")),

    Rule("openai_key", "OpenAI API key", "high",
         "An OpenAI API key.",
         _c(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),

    Rule("npm_token", "npm token", "high",
         "An npm access token.",
         _c(r"\bnpm_[0-9A-Za-z]{36}\b")),

    Rule("jwt", "JSON web token", "medium",
         "A JSON web token.",
         _c(r"\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b")),

    Rule("basic_auth_url", "Credentials in a url", "high",
         "A username and password embedded in a url.",
         _c(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:([^/\s:@]{3,})@"), 1),

    Rule("generic_secret_assignment", "Hardcoded secret", "medium",
         "A secret looking value assigned to a sensitive variable.",
         _c(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
         1, min_entropy=3.0),
]


GENERIC_ENTROPY_RULE = Rule(
    "high_entropy_string", "High entropy string", "low",
    "A long random looking string that may be a secret.",
    _c(r"[A-Za-z0-9+/=_\-]{20,}"), 0, min_entropy=4.3)


RULES_BY_ID = {r.id: r for r in DEFAULT_RULES + [GENERIC_ENTROPY_RULE]}
