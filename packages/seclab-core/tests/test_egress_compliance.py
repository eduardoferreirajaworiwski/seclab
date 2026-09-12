"""Regression guard: every outbound HTTP call in the workspace must go
through seclab.core.http.HttpProvider (which enforces EgressPolicy). A
module reaching for httpx/requests/urllib directly bypasses the
SSRF/DNS-rebinding protections HttpProvider provides - this test fails
the moment that happens, instead of relying on someone remembering to
grep for it during review."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ALLOWED_HTTPX_FILE = REPO_ROOT / "packages/seclab-core/src/seclab/core/http.py"
FORBIDDEN_IMPORTS = re.compile(r"^\s*(import (httpx|requests|urllib3)\b|from (httpx|requests|urllib3) )")

SEARCH_DIRS = ["packages", "apps"]


def _python_files() -> list[Path]:
    files = []
    for base in SEARCH_DIRS:
        for path in (REPO_ROOT / base).rglob("*.py"):
            if "/tests/" in path.as_posix() or "\\tests\\" in str(path):
                continue
            if path == ALLOWED_HTTPX_FILE:
                continue
            files.append(path)
    return files


def test_no_module_imports_a_raw_http_client_directly():
    violations = []
    for path in _python_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if FORBIDDEN_IMPORTS.match(line):
                violations.append(f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}")
    assert not violations, (
        "Found direct httpx/requests/urllib3 usage outside seclab.core.http.HttpProvider:\n"
        + "\n".join(violations)
    )
