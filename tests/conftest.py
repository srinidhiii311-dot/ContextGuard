import os

# Ensure required environment variables exist for testing without hardcoded production fallbacks
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-at-least-16-chars-min")
os.environ.setdefault("AUDIT_HMAC_SECRET", "test-audit-hmac-secret-at-least-16-chars-min")
os.environ.setdefault("GATE_API_SECRET", "test-gate-api-secret-min-32-chars-xx")
# Disable gate auth for the main test suite so existing tests continue to pass
os.environ.setdefault("GATE_AUTH_ENABLED", "false")
