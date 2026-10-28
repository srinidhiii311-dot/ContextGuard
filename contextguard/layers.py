"""
contextguard/layers.py — Canonical Defense-in-Depth Layer Registry (G7 & Gap 4)

Defines the single authoritative list of defense layers implemented in ContextGuard.
Guarantees alignment between codebase registration, architectural documentation,
and acceptance test verification.
"""

from __future__ import annotations

from typing import List, NamedTuple


class LayerDefinition(NamedTuple):
    layer_id: str
    constant_name: str
    canonical_name: str
    component_module: str
    description: str


REGISTERED_LAYERS: List[LayerDefinition] = [
    LayerDefinition(
        layer_id="L0",
        constant_name="LAYER_L0_EGRESS_GUARD",
        canonical_name="Egress & Dispatch Guard",
        component_module="agent.browser_controller",
        description="Network egress boundary, origin allowlisting via context.route, popup & download control."
    ),
    LayerDefinition(
        layer_id="L1",
        constant_name="LAYER_L1_INTENT_LOCK",
        canonical_name="Intent Anchor & Schema Lock",
        component_module="contextguard.gate",
        description="Ingests user prompt into immutable TrustedIntent dataclass; locks parameters at initialization."
    ),
    LayerDefinition(
        layer_id="L2",
        constant_name="LAYER_L2_THREAT_TAXONOMY",
        canonical_name="Known Threat Taxonomy Classifier",
        component_module="contextguard.threat_detector",
        description="Regex and pattern hint matcher across 7 threat categories and 49 attack indicators."
    ),
    LayerDefinition(
        layer_id="L3",
        constant_name="LAYER_L3_LEXICAL_DEVIATION",
        canonical_name="Lexical n-gram Vector Space Cosine Deviation",
        component_module="contextguard.threat_characterizer",
        description="Deterministic sub-word 3-gram log-frequency cosine deviation (NOT neural foundation model embeddings)."
    ),
    LayerDefinition(
        layer_id="L4",
        constant_name="LAYER_L4_DOM_BASELINE",
        canonical_name="DOM Baseline Region Hash Verifier",
        component_module="contextguard.dom_baseline",
        description="Per-route region hash comparison with dynamic attribute masking to detect unapproved form drift."
    ),
    LayerDefinition(
        layer_id="L5",
        constant_name="LAYER_L5_HIDDEN_CONTENT",
        canonical_name="Computed-Style Hidden Content Scanner",
        component_module="contextguard.hidden_content",
        description="Playwright computed styles inspection (getComputedStyle) to detect invisible text cloaking."
    ),
    LayerDefinition(
        layer_id="L6",
        constant_name="LAYER_L6_CHAIN_DETECTOR",
        canonical_name="Stateful Trajectory Chain Detector",
        component_module="contextguard.chain_detector",
        description="Multi-step sliding window state machine detecting staged evasion patterns across action sequences."
    ),
    LayerDefinition(
        layer_id="L7",
        constant_name="LAYER_L7_LLM_CHECKER",
        canonical_name="Selective Grey-Zone LLM Reviewer",
        component_module="contextguard.llm_checker",
        description="Invoked strictly when risk score is in the ambiguous 30-59 band; operates in raise-only mode."
    ),
    LayerDefinition(
        layer_id="L8",
        constant_name="LAYER_L8_HARD_RULE_FLOOR",
        canonical_name="Deterministic Hard-Rule Floor & Price Cap",
        component_module="contextguard.consistency_checker",
        description="Unconditional final checks: navigation boundary lock, field matching, and fee_floor() price cap."
    ),
    LayerDefinition(
        layer_id="L9",
        constant_name="LAYER_L9_POLICY_ENGINE",
        canonical_name="Continuous Risk & Policy Engine",
        component_module="contextguard.policy_engine",
        description="Multi-factor continuous risk score mapping to graduated decisions: ALLOW, CONFIRM, BLOCK."
    ),
    LayerDefinition(
        layer_id="L10",
        constant_name="LAYER_L10_HUMAN_APPROVAL",
        canonical_name="Human-in-the-Loop Approval State Machine",
        component_module="contextguard.approvals",
        description="Role-based JWT authorization, multi-approver threshold for high risk, and fail-closed timeout."
    ),
    LayerDefinition(
        layer_id="L11",
        constant_name="LAYER_L11_AUDIT_LOG",
        canonical_name="Tamper-Evident SHA-256 HMAC Audit Log",
        component_module="contextguard.audit_log",
        description="ACID SQLite transaction logging with backward-linked SHA-256 hash chains and periodic HMAC anchors."
    ),
]


def get_layer_ids() -> List[str]:
    return [layer.layer_id for layer in REGISTERED_LAYERS]


def get_layer_count() -> int:
    return len(REGISTERED_LAYERS)
