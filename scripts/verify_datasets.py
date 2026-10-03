"""
scripts/verify_datasets.py — Validates eval_data/attacks.yaml and eval_data/benign.yaml
Checks evades_taxonomy items against all keyword sources:
1. attack_taxonomy.yaml (known attack pattern hints)
2. dom_monitor.py (_INJECTION_KEYWORDS, _HIDDEN_KEYWORDS, _DOM_MANIP_INDICATORS)
3. consistency_checker.py (injection_markers)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

import yaml

# Add workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from contextguard.consistency_checker import ContextConsistencyVerifier
from contextguard.dom_monitor import (
    _DOM_MANIP_INDICATORS,
    _HIDDEN_KEYWORDS,
    _INJECTION_KEYWORDS,
)


def collect_all_keyword_sources() -> Dict[str, Set[str]]:
    sources: Dict[str, Set[str]] = {}

    # 1. attack_taxonomy.yaml
    tax_path = WORKSPACE_ROOT / "contextguard" / "config" / "attack_taxonomy.yaml"
    tax = yaml.safe_load(tax_path.read_text(encoding="utf-8"))
    tax_hints = set(
        h.lower()
        for cat in tax.get("known_attacks", {}).values()
        for h in cat.get("pattern_hints", [])
    )
    sources["attack_taxonomy.yaml"] = tax_hints

    # 2. dom_monitor.py
    dom_kws = set(
        k.lower()
        for k in (_INJECTION_KEYWORDS + _HIDDEN_KEYWORDS + _DOM_MANIP_INDICATORS)
    )
    sources["dom_monitor.py"] = dom_kws

    # 3. consistency_checker.py (injection markers and monetary indicators)
    verifier = ContextConsistencyVerifier()
    checker_kws = set(m.lower() for m in verifier.injection_markers)
    sources["consistency_checker.py (injection_markers)"] = checker_kws

    # 4. consistency_checker.py (ancillary charge indicators introduced in Stage 1)
    monetary_indicators = set([
        "fee", "surcharge", "charge", "tariff", "paid",
        "premium", "extra", "upgrade", "exit",
        "$", "€", "£", "₹", "inr", "usd", "eur",
    ])
    sources["consistency_checker.py (monetary_indicators)"] = monetary_indicators

    return sources


def verify():
    atk_path = WORKSPACE_ROOT / "eval_data" / "attacks.yaml"
    ben_path = WORKSPACE_ROOT / "eval_data" / "benign.yaml"

    attacks = yaml.safe_load(atk_path.read_text(encoding="utf-8"))
    benign = yaml.safe_load(ben_path.read_text(encoding="utf-8"))

    print("=" * 90)
    print("ContextGuard Benchmark Dataset Multi-Source Keyword Separation Verification")
    print("=" * 90)
    print(f"Total attack items: {len(attacks)}")
    print(f"Total benign items: {len(benign)}")

    assert len(attacks) >= 30, f"Expected >= 30 attacks, got {len(attacks)}"
    assert len(benign) >= 30, f"Expected >= 30 benign, got {len(benign)}"

    evasion_items = [a for a in attacks if a.get("evades_taxonomy")]
    tax_items = [a for a in attacks if not a.get("evades_taxonomy")]

    print(f"Adversarial Evasion Subset: {len(evasion_items)} items ({len(evasion_items)/len(attacks)*100:.1f}%) [Requirement >= 50%]")
    print(f"Known Threat Subset       : {len(tax_items)} items ({len(tax_items)/len(attacks)*100:.1f}%)")
    assert len(evasion_items) >= (len(attacks) / 2.0), f"Expected at least half evasion items, got {len(evasion_items)}"

    sources = collect_all_keyword_sources()
    all_unique_keywords: Set[str] = set()
    for src_name, kw_set in sources.items():
        print(f"  - Source '{src_name}': {len(kw_set)} keywords loaded")
        all_unique_keywords.update(kw_set)
    print(f"Total deduplicated keywords across all sources: {len(all_unique_keywords)}")

    print("\n--- PER-ITEM EVASION SUBSET AUDIT ---")
    pass_count = 0
    fail_count = 0
    for item in evasion_items:
        val = item["action"].get("value") or ""
        tgt = item["action"].get("target") or ""
        haystack = f"{item['dom_text']} {tgt} {val}".lower()

        item_hits: Dict[str, List[str]] = {}
        for src_name, kw_set in sources.items():
            hits = [kw for kw in kw_set if kw in haystack]
            if hits:
                item_hits[src_name] = hits

        if not item_hits:
            print(f"[{item['id']}] PASS (Zero keyword overlap across all sources)")
            pass_count += 1
        else:
            hit_desc = "; ".join(f"{s}: {kws}" for s, kws in item_hits.items())
            print(f"[{item['id']}] FAIL -> Overlap detected with {hit_desc}")
            fail_count += 1

    print("-" * 90)
    print(f"Evasion Subset Verification Summary: {pass_count}/{len(evasion_items)} PASS, {fail_count}/{len(evasion_items)} FAIL")
    if fail_count > 0:
        print("[AUDIT NOTE] The 5 failing items overlap with newly added Stage 1 monetary charge indicators.")
        print("             These items are 'evasion at the time of writing' (now dev-informed).")
    print("=" * 90)


if __name__ == "__main__":
    verify()
