"""Least-privilege tool authorization per agent.

Each agent may only call the MCP tools listed for it. Tools in
``APPROVAL_REQUIRED`` additionally need a single-use approval token minted when
a human approves the action (see ``ApprovalTokens``).
"""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass

POLICY: dict[str, list[str]] = {
    "supervisor": [],
    "planner": [],
    "research": ["docs.*"],
    "observability": ["observability.*"],
    "code": ["git.search_repository", "git.read_file", "git.git_log", "git.git_show", "git.git_diff",
             "git.git_blame", "git.find_symbol", "git.list_deploys", "git.show_file_at"],
    "database": ["database.get_schema", "database.execute_readonly_sql", "database.explain_query"],
    "memory": [],
    "rca": [],
    "verification": ["git.read_file", "git.show_file_at", "git.list_deploys",
                     "observability.export_traffic_sample", "sandbox.*"],
    "fix": ["git.read_file", "git.show_file_at", "git.git_diff", "git.git_show", "git.list_deploys",
            "git.search_repository", "observability.export_traffic_sample", "git.create_fix_branch", "ops.*",
            "sandbox.*"],
}

APPROVAL_REQUIRED = {"git.create_fix_branch", "ops.set_feature_flag", "ops.rotate_certificate",
                     "ops.execute_write_sql"}

ACCESS_LEVEL = {
    "research": "read-only", "observability": "read-only", "code": "read-only", "database": "read-only (SQL)",
    "verification": "read-only + sandbox", "fix": "sandbox write; production actions need approval",
    "supervisor": "no tools", "planner": "no tools", "memory": "memory store", "rca": "no tools",
}


class PermissionDenied(Exception):
    pass


def is_allowed(agent: str, tool: str) -> bool:
    return any(fnmatch.fnmatch(tool, pat) for pat in POLICY.get(agent, []))


@dataclass
class ApprovalToken:
    token: str
    tool: str
    run_id: str
    expires_at: float


class ApprovalTokens:
    """HMAC-signed, single-use, time-limited tokens binding an approval to one tool + run."""

    def __init__(self, key: bytes | None = None):
        self._key = key or os.environ.get("AEGIS_APPROVAL_KEY", "").encode() or secrets.token_bytes(32)
        self._used: set[str] = set()

    def mint(self, tool: str, run_id: str, ttl_s: int = 900) -> str:
        expires = int(time.time()) + ttl_s
        nonce = secrets.token_hex(8)
        msg = f"{tool}|{run_id}|{expires}|{nonce}"
        sig = hmac.new(self._key, msg.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{msg}|{sig}"

    def verify(self, token: str | None, tool: str, run_id: str) -> bool:
        if not token or token in self._used:
            return False
        try:
            t_tool, t_run, expires, nonce, sig = token.split("|")
        except ValueError:
            return False
        msg = f"{t_tool}|{t_run}|{expires}|{nonce}"
        good = hmac.new(self._key, msg.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(good, sig) or t_tool != tool or t_run != run_id:
            return False
        if int(expires) < time.time():
            return False
        self._used.add(token)
        return True


approval_tokens = ApprovalTokens()


def authorize(agent: str, tool: str, run_id: str | None, approval_token: str | None = None) -> None:
    if not is_allowed(agent, tool):
        raise PermissionDenied(f"agent '{agent}' is not permitted to call '{tool}'")
    if tool in APPROVAL_REQUIRED and not approval_tokens.verify(approval_token, tool, run_id or ""):
        raise PermissionDenied(f"'{tool}' requires a valid human approval token")
