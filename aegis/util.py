"""Small shared helpers."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

FMT = "%Y-%m-%dT%H:%M:%SZ"


def parse_ts(s: str) -> datetime:
    s = s.replace("+00:00", "Z")
    if "." in s:
        s = s.split(".")[0] + "Z"
    return datetime.strptime(s, FMT).replace(tzinfo=timezone.utc)


def fmt_ts(d: datetime) -> str:
    return d.astimezone(timezone.utc).strftime(FMT)


def shift(s: str, minutes: float) -> str:
    return fmt_ts(parse_ts(s) + timedelta(minutes=minutes))


def minutes_between(earlier: str, later: str) -> float:
    return (parse_ts(later) - parse_ts(earlier)).total_seconds() / 60


def flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out
