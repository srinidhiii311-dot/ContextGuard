"""
adaptive/verify_redesigned_s4_s5.py — Verification of Redesigned S4 and S5 sets.

Verifies:
- S4: Proposed action does NOT deviate from intent on mapped fields (action is consistent with intent).
- S5: Every individual step is consistent with locked intent and allowlist when checked alone,
      and harm exists only in the combination.
Drops any failing variants and reports counts.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from adaptive.redesign_s4_s5 import (
    generate_all_redesigned_variants,
    generate_redesigned_s4_variants,
    generate_redesigned_s5_variants,
    DOMAINS,
)
from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.gate import ProposedAction
from gateway.loader import Gateway
from harness.run_case import build_trusted_intent_from_dict
from harness.oracle_v3 import DOMAIN_ALLOWLISTS

def verify_s4_variants(variants: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    passed = []
    dropped = []

    for v in variants:
        dom = v["domain"]
        intent = v["locked_intent"]
        act_dict = v["proposed_action"]
        tgt = act_dict.get("target", "").lower()
        val = str(act_dict.get("value", "")).lower()

        # Check mapped fields against intent
        deviates = False
        if "to" in tgt and "destination" in intent:
            if val != str(intent["destination"]).lower():
                deviates = True
        elif "payee" in tgt and "payee" in intent:
            if val != str(intent["payee"]).lower():
                deviates = True
        elif "address" in tgt and "address" in intent:
            if val != str(intent["address"]).lower():
                deviates = True
        elif "doctor" in tgt and "doctor" in intent:
            if val != str(intent["doctor"]).lower():
                deviates = True
        elif "to-email" in tgt and "to_email" in intent:
            if val != str(intent["to_email"]).lower():
                deviates = True

        if deviates:
            dropped.append(v)
        else:
            passed.append(v)

    return passed, dropped

def verify_s5_variants(variants: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    passed = []
    dropped = []
    gw_cache = {d: Gateway.from_domain(d) for d in DOMAINS}

    for v in variants:
        dom = v["domain"]
        intent_dict = v["locked_intent"]
        intent = build_trusted_intent_from_dict(dom, intent_dict)
        gw = gw_cache[dom]
        gw.set_intent(intent)

        prep_dict = v.get("prep_action", {})
        step2_dict = v.get("proposed_action", {})

        p_act = ProposedAction(
            action_type=prep_dict["action_type"],
            target=prep_dict["target"],
            value=prep_dict.get("value"),
            page_url=prep_dict["page_url"],
        )
        s2_act = ProposedAction(
            action_type=step2_dict["action_type"],
            target=step2_dict["target"],
            value=step2_dict.get("value"),
            page_url=step2_dict["page_url"],
        )

        # Check step 1 alone on consistency checker
        rep1 = gw.verifier.verify(intent, p_act, dom_text="")
        # Check step 2 alone on consistency checker
        rep2 = gw.verifier.verify(intent, s2_act, dom_text="")

        # Allowlist check for both
        allowlist = DOMAIN_ALLOWLISTS.get(dom, set())
        from urllib.parse import urlparse
        u1_host = urlparse(p_act.page_url).netloc
        u2_host = urlparse(s2_act.page_url).netloc

        is_step1_clean = rep1.is_consistent and (u1_host in allowlist)
        is_step2_clean = rep2.is_consistent and (u2_host in allowlist)

        if is_step1_clean and is_step2_clean:
            passed.append(v)
        else:
            dropped.append((v, rep1.inconsistencies, rep2.inconsistencies))

    return passed, dropped

if __name__ == "__main__":
    s4_vars = []
    s5_vars = []
    for d in DOMAINS:
        s4_vars.extend(generate_redesigned_s4_variants(d, count=40))
        s5_vars.extend(generate_redesigned_s5_variants(d, count=40))

    s4_pass, s4_drop = verify_s4_variants(s4_vars)
    s5_pass, s5_drop = verify_s5_variants(s5_vars)

    print(f"S4 Verification: {len(s4_pass)} PASSED, {len(s4_drop)} DROPPED (out of {len(s4_vars)})")
    print(f"S5 Verification: {len(s5_pass)} PASSED, {len(s5_drop)} DROPPED (out of {len(s5_vars)})")
    if s5_drop:
        print("S5 drop sample reason:")
        for v, inc1, inc2 in s5_drop[:2]:
            print("  Variant:", v["variant_id"])
            print("  Step 1 inconsistencies:", [i.detail for i in inc1])
            print("  Step 2 inconsistencies:", [i.detail for i in inc2])
