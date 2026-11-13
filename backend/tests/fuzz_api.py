"""Property-based API fuzzing with Schemathesis (dev only; slow, so not collected by the default test run).

    pip install schemathesis
    FUZZ_EXAMPLES=100 pytest tests/fuzz_api.py -p no:cacheprovider

It generates requests from the app's own OpenAPI schema (valid and deliberately malformed), sends them as a
logged-in admin to a throwaway app, and fails on any 5xx response or on a response that breaks the declared
contract for server errors. Session-changing endpoints (password, MFA, logout) are skipped: they would sign the
fuzzer out and add nothing a 5xx check can find that test_mfa.py does not already exercise.
"""

import os
import tempfile
from pathlib import Path

import pytest
import schemathesis
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, settings
from schemathesis.checks import not_a_server_error

from app.core.config import Config
from app.main import create_app

_tmp = tempfile.TemporaryDirectory()
_app = create_app(Config(data_dir=Path(_tmp.name), frontend_dir=Path(_tmp.name) / "none", scheduler_enabled=False))
_client = TestClient(_app)
_client.__enter__()  # runs migrations
_client.post("/api/auth/setup", json={"username": "admin", "password": "correct horse battery"})
HEADERS = {"Cookie": f"ga_session={_client.cookies['ga_session']}"}

schema = schemathesis.openapi.from_asgi("/api/openapi.json", _app, headers=HEADERS)


@schema.exclude(path_regex=r"^/api/auth/(password|logout|mfa)").parametrize()
@settings(max_examples=int(os.environ.get("FUZZ_EXAMPLES", "40")), deadline=None, suppress_health_check=list(HealthCheck))
def test_no_server_errors(case):
    response = case.call(headers=HEADERS)
    case.validate_response(response, checks=[not_a_server_error])


def teardown_module(_module):
    _client.__exit__(None, None, None)
    _tmp.cleanup()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider", "-q"]))
