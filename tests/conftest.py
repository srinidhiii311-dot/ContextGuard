import os
import pytest

# Ensure required environment variables exist for testing without hardcoded production fallbacks
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-at-least-16-chars-min")
os.environ.setdefault("AUDIT_HMAC_SECRET", "test-audit-hmac-secret-at-least-16-chars-min")
os.environ.setdefault("GATE_API_SECRET", "test-gate-api-secret-min-32-chars-xx")
# Disable gate auth for the main test suite so existing tests continue to pass
os.environ.setdefault("GATE_AUTH_ENABLED", "false")


@pytest.fixture(autouse=True)
def isolate_test_audit_log(tmp_path):
    """Sets GATEWAY_AUDIT_LOG_PATH to a temporary file for every test to prevent polluting runs/."""
    temp_audit_file = str(tmp_path / "test_audit.jsonl")
    old_val = os.environ.get("GATEWAY_AUDIT_LOG_PATH")
    os.environ["GATEWAY_AUDIT_LOG_PATH"] = temp_audit_file
    yield temp_audit_file
    if old_val is not None:
        os.environ["GATEWAY_AUDIT_LOG_PATH"] = old_val
    else:
        os.environ.pop("GATEWAY_AUDIT_LOG_PATH", None)
