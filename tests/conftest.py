import os
import tempfile
from pathlib import Path

import pytest

_tmp = tempfile.mkdtemp(prefix="aegis-test-")
os.environ["AEGIS_DATA_DIR"] = _tmp
os.environ.setdefault("AEGIS_PROVIDER", "offline")


@pytest.fixture(scope="session")
def demo_ws(tmp_path_factory) -> Path:
    from aegis.world.generator import build_workspace, demo_spec
    return build_workspace(demo_spec("payment-db-timeout"), tmp_path_factory.mktemp("ws") / "demo")


@pytest.fixture(scope="session")
def flag_ws(tmp_path_factory) -> Path:
    from aegis.world.generator import build_workspace, demo_spec
    return build_workspace(demo_spec("checkout-flag"), tmp_path_factory.mktemp("ws") / "flag")
