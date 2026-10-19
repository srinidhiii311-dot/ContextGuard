import os

# Ensure required environment variables exist for testing without hardcoded production fallbacks
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-at-least-16-chars-min")
os.environ.setdefault("AUDIT_HMAC_SECRET", "test-audit-hmac-secret-at-least-16-chars-min")
