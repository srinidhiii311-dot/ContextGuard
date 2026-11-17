import os
import pytest

# Ensure required environment variables exist for testing without hardcoded production fallbacks
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-at-least-16-chars-min")
os.environ.setdefault("AUDIT_HMAC_SECRET", "test-audit-hmac-secret-at-least-16-chars-min")
os.environ.setdefault("GATE_API_SECRET", "test-gate-api-secret-min-32-chars-xx")


@pytest.fixture
def gate_token_factory():
    """Factory fixture to issue real session tokens for test tasks."""
    from backend.api.gate_auth import issue_session_token
    def _issue(task_id: str) -> str:
        return issue_session_token(task_id)
    return _issue


@pytest.fixture(autouse=True)
def isolate_test_audit_log(tmp_path):
    """Sets GATEWAY_AUDIT_LOG_PATH and LLM_LOG_PATH to temporary files for every test to prevent polluting runs/."""
    temp_audit_file = str(tmp_path / "test_audit.jsonl")
    temp_llm_file = str(tmp_path / "test_llm_calls.jsonl")
    old_audit = os.environ.get("GATEWAY_AUDIT_LOG_PATH")
    old_llm = os.environ.get("LLM_LOG_PATH")
    old_llm_calls = os.environ.get("LLM_CALLS_LOG_PATH")

    os.environ["GATEWAY_AUDIT_LOG_PATH"] = temp_audit_file
    os.environ["LLM_LOG_PATH"] = temp_llm_file
    os.environ["LLM_CALLS_LOG_PATH"] = temp_llm_file
    yield temp_audit_file
    if old_audit is not None:
        os.environ["GATEWAY_AUDIT_LOG_PATH"] = old_audit
    else:
        os.environ.pop("GATEWAY_AUDIT_LOG_PATH", None)
    if old_llm is not None:
        os.environ["LLM_LOG_PATH"] = old_llm
    else:
        os.environ.pop("LLM_LOG_PATH", None)
    if old_llm_calls is not None:
        os.environ["LLM_CALLS_LOG_PATH"] = old_llm_calls
    else:
        os.environ.pop("LLM_CALLS_LOG_PATH", None)
