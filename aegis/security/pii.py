"""PII and secret detection with masking.

Applied to every tool result before it reaches an agent or an LLM, and to the
final report. Card numbers are only masked when they pass the Luhn check to
avoid mangling ordinary long integers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?!acme\.dev\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"\+\d{1,3}-\d{3}-\d{3}-\d{4}\b")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SECRETS: list[tuple[str, re.Pattern]] = [
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("db_password", re.compile(r"(?<=://)([^:/@\s]+):([^@\s]+)(?=@)")),
    ("generic_secret", re.compile(r"(?i)\b(api[_-]?key|secret|password|token)\s*[=:]\s*['\"]?([^\s'\"]{8,})")),
]


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass
class Redaction:
    kind: str
    count: int


def redact_text(text: str) -> tuple[str, dict[str, int]]:
    found: dict[str, int] = {}

    def bump(kind: str) -> None:
        found[kind] = found.get(kind, 0) + 1

    for kind, pattern in SECRETS:
        def repl(m: re.Match, kind=kind) -> str:
            bump(kind)
            if kind == "db_password":
                return f"{m.group(1)}:[REDACTED]"
            if kind == "generic_secret":
                return f"{m.group(1)}=[REDACTED]"
            return f"[REDACTED_{kind.upper()}]"
        text = pattern.sub(repl, text)

    def card_repl(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            bump("card_number")
            return f"[CARD ****{digits[-4:]}]"
        return m.group(0)

    text = CARD.sub(card_repl, text)

    def email_repl(m: re.Match) -> str:
        bump("email")
        return "[EMAIL]"

    text = EMAIL.sub(email_repl, text)

    def phone_repl(m: re.Match) -> str:
        bump("phone")
        return "[PHONE]"

    text = PHONE.sub(phone_repl, text)
    return text, found


def redact(obj: Any) -> tuple[Any, dict[str, int]]:
    """Recursively redact strings inside JSON-like structures."""
    totals: dict[str, int] = {}

    def merge(found: dict[str, int]) -> None:
        for k, v in found.items():
            totals[k] = totals.get(k, 0) + v

    def walk(node: Any) -> Any:
        if isinstance(node, str):
            new, found = redact_text(node)
            merge(found)
            return new
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(obj), totals


def scan_secrets(text: str) -> list[str]:
    """Names of secret patterns present in ``text`` (used to vet generated patches)."""
    return [kind for kind, pattern in SECRETS if pattern.search(text)]
