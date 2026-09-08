# ContextGuard package — Phase 5
from contextguard.gate import (
    ContextGuardGate,
    Decision,
    TrustedIntent,
    ProposedAction,
    GateResult,
)
from contextguard.url_monitor import URLMonitor, url_monitor
from contextguard.dom_monitor import DOMMonitor, dom_monitor
from contextguard.action_analyzer import ActionAnalyzer, action_analyzer
from contextguard.consistency_checker import ConsistencyChecker, consistency_checker
from contextguard.risk_engine import RiskEngine, risk_engine
from contextguard.context_store import ContextStore, context_store
from contextguard.intervention import build_intervention_hook

__all__ = [
    "ContextGuardGate",
    "Decision",
    "TrustedIntent",
    "ProposedAction",
    "GateResult",
    "URLMonitor",
    "url_monitor",
    "DOMMonitor",
    "dom_monitor",
    "ActionAnalyzer",
    "action_analyzer",
    "ConsistencyChecker",
    "consistency_checker",
    "RiskEngine",
    "risk_engine",
    "ContextStore",
    "context_store",
    "build_intervention_hook",
]
