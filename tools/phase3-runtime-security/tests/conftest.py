from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from mock_app import TRUSTED_ORIGIN, MockServer

from runtime_security.config import parse
from runtime_security.runner import run_all
from runtime_security.utils.http import Client


def make_cfg(base_url: str, **overrides):
    data = {
        "target": {"base_url": base_url, "environment": "local", "production": False},
        "cors": {"allowed_origins": [TRUSTED_ORIGIN]},
        "error_leakage": {"invalid_resource_path": "/api/items/not-a-valid-id", "missing_parameter_path": "/api/search"},
        "limits": {"delay_seconds": 0},
    }
    for key, value in overrides.items():
        section, _, field = key.partition("__")
        data.setdefault(section, {})[field] = value
    return parse(data)


def client_for(cfg):
    return Client(cfg)


@pytest.fixture(scope="module")
def safe_app():
    with MockServer("safe") as s:
        yield s


@pytest.fixture(scope="module")
def unsafe_app():
    with MockServer("unsafe") as s:
        yield s


def ids(run):
    return {r.name for r in run.results}


def failed(run):
    return {r.name for r in run.results if r.outcome.value == "FAILED"}


def full_report(base_url: str, **overrides):
    return run_all(make_cfg(base_url, **overrides))


def make_cert(tmp: Path, name: str, san: str) -> tuple[str, str]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = tmp / f"{name}.crt", tmp / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "30", "-subj", "/CN=phase3-test", "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True, shell=False,
    )
    return str(cert), str(key)
