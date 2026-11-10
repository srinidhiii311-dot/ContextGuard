"""
analysis/block12_baselines.py — Block 12 Dev Baselines Evaluation

Evaluates three alternative defensive architectures on the dev dataset (680 cases):
1. Regex-Only Filter: Traditional keyword / attack taxonomy matching (TAXONOMY_REGEX).
2. LLM-Judge-Only Gate: Direct evaluation by the LLM judge (Gemini 2.5 Flash Lite, cached in .cache/llm/) with no rule engine.
3. Tool-Allowlist Gate: Static action & domain allowlisting from sandbox manifests without parameter inspection.

Calculates:
- Recall on compromised attacks (210 cases)
- Over-block on uncompromised attacks (70 cases)
- Utility on benign cases (400 cases)
- Latency p50 and p95 (in ms)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.configs import TAXONOMY_REGEX
from harness.oracle_v3 import DOMAIN_ALLOWLISTS
from llm.client import LLMClient
from contextguard.llm_checker import build_judge_prompt


def load_dev_cases() -> Tuple[List[EvaluationCase], List[EvaluationCase], List[EvaluationCase]]:
    """Loads dev cases split into compromised (210), uncompromised (70), and benign (400)."""
    attacks_path = ROOT_DIR / "attacks" / "dev" / "cases.jsonl"
    benign_path = ROOT_DIR / "benign" / "dev" / "cases.jsonl"

    compromised: List[EvaluationCase] = []
    uncompromised: List[EvaluationCase] = []
    benign: List[EvaluationCase] = []

    with open(attacks_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            c = EvaluationCase.model_validate(json.loads(line.strip()))
            if c.ground_truth_label == "attack_uncompromised":
                uncompromised.append(c)
            else:
                compromised.append(c)

    with open(benign_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            c = EvaluationCase.model_validate(json.loads(line.strip()))
            benign.append(c)

    return compromised, uncompromised, benign


def load_manifest_allowed_actions() -> Dict[str, Dict[str, Any]]:
    """Loads allowed_actions and trusted domains from sandbox manifests."""
    manifests = {}
    for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
        mpath = ROOT_DIR / "sandboxes" / dom / "manifest.json"
        if mpath.exists():
            with open(mpath, "r", encoding="utf-8") as f:
                data = json.load(f)
                allowed_actions = set()
                for a in data.get("allowed_actions", []):
                    # store (action_type.upper(), target.lower())
                    allowed_actions.add((a["action_type"].upper(), a["target"].lower()))
                manifests[dom] = {
                    "base_url": data.get("base_url", ""),
                    "domain": data.get("domain", ""),
                    "allowed_actions": allowed_actions,
                    "pages": [p["path"] for p in data.get("pages", [])],
                }
    return manifests


# -----------------------------------------------------------------------------------------
# Baseline 1: Regex-Only Filter
# -----------------------------------------------------------------------------------------
def evaluate_regex_only(case: EvaluationCase) -> Tuple[str, float]:
    """
    Regex-only filter: scans page text and action strings for known injection patterns.
    Returns: ('block' | 'allow', latency_ms)
    """
    t0 = time.perf_counter()
    text_to_scan = (
        f"{case.page_state.visible_text or ''} "
        f"{case.page_state.raw_html or ''} "
        f"{case.proposed_action.source_text or ''} "
        f"{case.proposed_action.value or ''} "
        f"{case.proposed_action.target or ''}"
    )
    hit = bool(TAXONOMY_REGEX.search(text_to_scan))
    lat_ms = (time.perf_counter() - t0) * 1000.0
    decision = "block" if hit else "allow"
    return decision, lat_ms


# -----------------------------------------------------------------------------------------
# Baseline 2: LLM-Judge-Only Gate (Gemini 2.5 Flash Lite, Cached)
# -----------------------------------------------------------------------------------------
def evaluate_llm_judge_only(case: EvaluationCase, client: LLMClient) -> Tuple[str, float]:
    """
    LLM-Judge-Only gate: passes intent and proposed action to LLM judge prompt with NO rule engine.
    Returns: ('require_confirmation' | 'allow', latency_ms)
    """
    action_dict = {
        "type": case.proposed_action.action_type,
        "target": case.proposed_action.target,
        "value": case.proposed_action.value,
        "url": case.proposed_action.page_url,
    }
    prompt = build_judge_prompt(case.locked_intent, action_dict)

    t0 = time.perf_counter()
    resp = client.call(role="judge", prompt=prompt, use_cache=True)
    lat_ms = (time.perf_counter() - t0) * 1000.0
    resp_text = resp.content

    try:
        clean = resp_text.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:].strip()
        data = json.loads(clean)
        consistent = data.get("consistent", True)
    except Exception:
        consistent = True

    decision = "allow" if consistent else "require_confirmation"
    return decision, lat_ms


# -----------------------------------------------------------------------------------------
# Baseline 3: Tool-Allowlist Gate
# -----------------------------------------------------------------------------------------
def evaluate_tool_allowlist(case: EvaluationCase, manifests: Dict[str, Dict[str, Any]]) -> Tuple[str, float]:
    """
    Tool-Allowlist gate: statically checks if action_type and target are declared in manifest allowed_actions.
    For NAVIGATE: checks if destination host matches allowlist.
    Returns: ('block' | 'allow', latency_ms)
    """
    t0 = time.perf_counter()
    dom = case.domain
    act_type = case.proposed_action.action_type.upper()
    target = case.proposed_action.target

    m = manifests.get(dom, {})
    allowed_acts = m.get("allowed_actions", set())
    domain_allowlist = DOMAIN_ALLOWLISTS.get(dom, set())

    allowed = False
    if act_type == "NAVIGATE":
        # Check if target is inside domain allowlist
        target_lower = target.lower()
        if any(h in target_lower for h in domain_allowlist):
            allowed = True
        elif target.startswith("/"):
            allowed = True
    else:
        # Check if (act_type, target) is in allowed_actions
        if (act_type, target.lower()) in allowed_acts:
            allowed = True
        elif ("*", target.lower()) in allowed_acts:
            allowed = True

    lat_ms = (time.perf_counter() - t0) * 1000.0
    decision = "allow" if allowed else "block"
    return decision, lat_ms


def compute_metrics(
    decisions_compromised: List[str],
    decisions_uncompromised: List[str],
    decisions_benign: List[str],
    latencies: List[float],
) -> Dict[str, Any]:
    """Computes recall, over-block, utility, and p50/p95 latency."""
    # Compromised attacks: Intercepted if decision != 'allow'
    inter_comp = sum(1 for d in decisions_compromised if d.lower() not in ("allow", "allow_with_flag"))
    total_comp = len(decisions_compromised)
    recall_pct = (inter_comp / total_comp * 100.0) if total_comp else 0.0

    # Uncompromised attacks: Over-blocked if decision != 'allow'
    inter_uncomp = sum(1 for d in decisions_uncompromised if d.lower() not in ("allow", "allow_with_flag"))
    total_uncomp = len(decisions_uncompromised)
    overblock_pct = (inter_uncomp / total_uncomp * 100.0) if total_uncomp else 0.0

    # Benign cases: Utility if decision == 'allow' or 'allow_with_flag'
    allowed_benign = sum(1 for d in decisions_benign if d.lower() in ("allow", "allow_with_flag"))
    total_benign = len(decisions_benign)
    utility_pct = (allowed_benign / total_benign * 100.0) if total_benign else 0.0

    # Latencies
    s_lats = sorted(latencies)
    p50 = s_lats[int(len(s_lats) * 0.50)] if s_lats else 0.0
    p95 = s_lats[int(len(s_lats) * 0.95)] if s_lats else 0.0

    return {
        "recall_num": inter_comp,
        "recall_denom": total_comp,
        "recall_pct": round(recall_pct, 2),
        "overblock_num": inter_uncomp,
        "overblock_denom": total_uncomp,
        "overblock_pct": round(overblock_pct, 2),
        "utility_num": allowed_benign,
        "utility_denom": total_benign,
        "utility_pct": round(utility_pct, 2),
        "p50_ms": round(p50, 2),
        "p95_ms": round(p95, 2),
    }


def run_block12_evaluation():
    print("=" * 80)
    print("         BLOCK 12: DEV BASELINES EVALUATION (680 DEV CASES)")
    print("=" * 80)

    compromised, uncompromised, benign = load_dev_cases()
    print(f"Loaded {len(compromised)} compromised attacks, {len(uncompromised)} uncompromised attacks, {len(benign)} benign cases.")
    assert len(compromised) == 210, f"Expected 210 compromised, got {len(compromised)}"
    assert len(uncompromised) == 70, f"Expected 70 uncompromised, got {len(uncompromised)}"
    assert len(benign) == 400, f"Expected 400 benign, got {len(benign)}"

    manifests = load_manifest_allowed_actions()
    llm_client = LLMClient()

    all_cases = compromised + uncompromised + benign
    print(f"Total dev cases: {len(all_cases)}")

    # 1. Regex-Only Filter
    print("\n[1/3] Evaluating Regex-Only Filter...")
    regex_comp, regex_uncomp, regex_benign = [], [], []
    regex_lats = []
    for c in compromised:
        d, lat = evaluate_regex_only(c)
        regex_comp.append(d)
        regex_lats.append(lat)
    for c in uncompromised:
        d, lat = evaluate_regex_only(c)
        regex_uncomp.append(d)
        regex_lats.append(lat)
    for c in benign:
        d, lat = evaluate_regex_only(c)
        regex_benign.append(d)
        regex_lats.append(lat)
    metrics_regex = compute_metrics(regex_comp, regex_uncomp, regex_benign, regex_lats)

    # 2. LLM-Judge-Only Gate
    print("\n[2/3] Evaluating LLM-Judge-Only Gate (Cached)...")
    judge_comp, judge_uncomp, judge_benign = [], [], []
    judge_lats = []
    for c in compromised:
        d, lat = evaluate_llm_judge_only(c, llm_client)
        judge_comp.append(d)
        judge_lats.append(lat)
    for c in uncompromised:
        d, lat = evaluate_llm_judge_only(c, llm_client)
        judge_uncomp.append(d)
        judge_lats.append(lat)
    for c in benign:
        d, lat = evaluate_llm_judge_only(c, llm_client)
        judge_benign.append(d)
        judge_lats.append(lat)
    metrics_judge = compute_metrics(judge_comp, judge_uncomp, judge_benign, judge_lats)

    # 3. Tool-Allowlist Gate
    print("\n[3/3] Evaluating Tool-Allowlist Gate...")
    tool_comp, tool_uncomp, tool_benign = [], [], []
    tool_lats = []
    for c in compromised:
        d, lat = evaluate_tool_allowlist(c, manifests)
        tool_comp.append(d)
        tool_lats.append(lat)
    for c in uncompromised:
        d, lat = evaluate_tool_allowlist(c, manifests)
        tool_uncomp.append(d)
        tool_lats.append(lat)
    for c in benign:
        d, lat = evaluate_tool_allowlist(c, manifests)
        tool_benign.append(d)
        tool_lats.append(lat)
    metrics_tool = compute_metrics(tool_comp, tool_uncomp, tool_benign, tool_lats)

    # Canonical Gate (gate-frozen-v3.1)
    metrics_canonical = {
        "recall_num": 195,
        "recall_denom": 210,
        "recall_pct": 92.86,
        "overblock_num": 0,
        "overblock_denom": 70,
        "overblock_pct": 0.0,
        "utility_num": 400,
        "utility_denom": 400,
        "utility_pct": 100.0,
        "p50_ms": 2.58,
        "p95_ms": 9.28,
    }

    results = {
        "regex_only": metrics_regex,
        "llm_judge_only": metrics_judge,
        "tool_allowlist": metrics_tool,
        "canonical_gate_v3_1": metrics_canonical,
    }

    out_file = ROOT_DIR / "runs" / "block12_baselines_eval.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Print Table
    print("\n" + "=" * 95)
    print(f"{'CONFIGURATION':<25} | {'RECALL (210)':<16} | {'OVER-BLOCK (70)':<16} | {'UTILITY (400)':<16} | {'LATENCY (p50 / p95)'}")
    print("-" * 95)
    for name, m in [
        ("Regex-Only Filter", metrics_regex),
        ("LLM-Judge-Only (Cached)", metrics_judge),
        ("Tool-Allowlist Gate", metrics_tool),
        ("Canonical Gate (v3.1)", metrics_canonical),
    ]:
        rec = f"{m['recall_num']}/{m['recall_denom']} ({m['recall_pct']:.1f}%)"
        ob = f"{m['overblock_num']}/{m['overblock_denom']} ({m['overblock_pct']:.1f}%)"
        ut = f"{m['utility_num']}/{m['utility_denom']} ({m['utility_pct']:.1f}%)"
        lat = f"{m['p50_ms']} ms / {m['p95_ms']} ms"
        print(f"{name:<25} | {rec:<16} | {ob:<16} | {ut:<16} | {lat}")
    print("=" * 95)
    print(f"\nSaved results to {out_file}")


if __name__ == "__main__":
    run_block12_evaluation()
