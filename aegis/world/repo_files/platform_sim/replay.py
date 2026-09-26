"""Load a service from a repository checkout and replay recorded traffic."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from platform_sim.core import ServiceModel, load_source, summarize

INDEX_CREATE = re.compile(r"CREATE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", re.I)
INDEX_DROP = re.compile(r"DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?(\w+)", re.I)


def pkg_name(service: str) -> str:
    return service.replace("-", "_")


def indexes_from_migrations(repo: Path) -> set[str]:
    indexes: set[str] = set()
    for path in sorted((repo / "migrations").glob("*.sql")):
        for line in path.read_text().splitlines():
            line = line.split("--", 1)[0]
            if m := INDEX_CREATE.search(line):
                indexes.add(m.group(1))
            elif m := INDEX_DROP.search(line):
                indexes.discard(m.group(1))
    return indexes


def load_service(repo: str | Path, service: str) -> ServiceModel:
    repo = Path(repo)
    pkg = pkg_name(service)
    base = repo / "services" / pkg
    config = yaml.safe_load((base / "config.yaml").read_text())
    rel = f"services/{pkg}/handlers.py"
    handlers = load_source((repo / rel).read_text(), rel)
    features = {}
    for feat in sorted((base / "features").glob("*.py")):
        if feat.name.startswith("_"):
            continue
        frel = f"services/{pkg}/features/{feat.name}"
        features[feat.stem] = load_source(feat.read_text(), frel)
    return ServiceModel(
        service=service,
        config=config,
        handler=getattr(handlers, config["handler"]),
        features=features,
        indexes=indexes_from_migrations(repo),
        table=config["db"]["table"],
        upstream_host=config["upstream"]["host"],
    )


def replay(repo: str | Path, service: str, traffic: list[dict], runtime: dict | None = None) -> dict:
    model = load_service(repo, service)
    outcomes = [model.handle(req, runtime) for req in sorted(traffic, key=lambda r: r["ts"])]
    report = summarize(outcomes)
    report["restarts"] = model.restarts
    return report
