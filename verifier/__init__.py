"""
ContextGuard verifier package.

Public API
----------
from verifier.capture_state import capture_state, PageSnapshot
from verifier.agent_claim   import extract_agent_claim, AgentClaim
from verifier.verifier      import ContextGuardVerifier, VerificationResult, VerificationStatus
from verifier.safe_actions  import safe_click, safe_fill, safe_navigate, safe_submit, execute_plan
"""

from verifier.capture_state import capture_state, PageSnapshot
from verifier.agent_claim   import extract_agent_claim, AgentClaim
from verifier.verifier      import (
    ContextGuardVerifier,
    VerificationResult,
    VerificationStatus,
    verifier,
)
from verifier.safe_actions  import (
    safe_click,
    safe_fill,
    safe_navigate,
    safe_submit,
    safe_extract,
    execute_plan,
    ActionOutcome,
)

__all__ = [
    "capture_state", "PageSnapshot",
    "extract_agent_claim", "AgentClaim",
    "ContextGuardVerifier", "VerificationResult", "VerificationStatus", "verifier",
    "safe_click", "safe_fill", "safe_navigate", "safe_submit",
    "safe_extract", "execute_plan", "ActionOutcome",
]
