"""Static validation of agent-generated SQL before it touches the replica."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

FORBIDDEN = re.compile(
    r"(?i)\b(insert|update|delete|drop|alter|create|replace|attach|detach|pragma|vacuum|reindex|"
    r"truncate|grant|revoke|load_extension)\b")
STRING_LIT = re.compile(r"'(?:[^']|'')*'")
TABLE_REF = re.compile(r"(?i)\b(?:from|join)\s+([A-Za-z_][\w]*)")
SENSITIVE_COLUMNS = {"card_number", "email", "phone"}
MAX_ROWS = 200


@dataclass
class SQLCheck:
    ok: bool
    sql: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate_sql(sql: str, allowed_tables: set[str]) -> SQLCheck:
    original = sql.strip().rstrip(";").strip()
    errors, warnings = [], []
    stripped = STRING_LIT.sub("''", original)
    if ";" in stripped:
        errors.append("multiple statements are not allowed")
    if not re.match(r"(?is)^\s*(select|with)\b", stripped):
        errors.append("only SELECT / WITH queries are allowed")
    if m := FORBIDDEN.search(stripped):
        errors.append(f"forbidden keyword: {m.group(1).upper()}")
    if "--" in stripped or "/*" in stripped:
        errors.append("SQL comments are not allowed")
    ctes = {c.lower() for c in re.findall(r"(?i)\b(\w+)\s+as\s*\(", stripped)}
    for table in TABLE_REF.findall(stripped):
        if table.lower() not in allowed_tables and table.lower() not in ctes:
            errors.append(f"table '{table}' is not in the allow-list")
    for col in SENSITIVE_COLUMNS:
        if re.search(rf"(?i)\b{col}\b", stripped) or re.search(r"(?i)select\s+\*\s+from\s+(customers|payments)", stripped):
            warnings.append("query touches PII columns; results will be masked")
            break
    sql_out = original
    if not errors and not re.search(r"(?i)\blimit\s+\d+\s*$", stripped):
        sql_out = f"{original} LIMIT {MAX_ROWS}"
    return SQLCheck(ok=not errors, sql=sql_out, errors=errors, warnings=warnings)
