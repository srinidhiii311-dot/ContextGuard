"""
analysis/run_baselines_on_hard_60.py — Evaluates Regex-Only, Tool-Allowlist, and LLM-Judge-Only on dev_hard_60.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import time

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from harness.case_schema import EvaluationCase
from harness.configs import TAXONOMY_REGEX
from harness.oracle_v3 import DOMAIN_ALLOWLISTS

with open("data/dev_hard_60.jsonl", "r", encoding="utf-8") as f:
    cases = [EvaluationCase.model_validate(json.loads(line)) for line in f if line.strip()]

manifests = {}
for dom in ["flight", "banking", "ecommerce", "healthcare", "email"]:
    mpath = ROOT_DIR / "sandboxes" / dom / "manifest.json"
    if mpath.exists():
        with open(mpath, "r", encoding="utf-8") as f:
            data = json.load(f)
            allowed_actions = set()
            for a in data.get("allowed_actions", []):
                allowed_actions.add((a["action_type"].upper(), a["target"].lower()))
            manifests[dom] = {
                "base_url": data.get("base_url", ""),
                "allowed_actions": allowed_actions,
            }

cats = [
    "semantically_off_task_mapped",
    "legitimate_unmapped_action",
    "paraphrased_injection_no_lexicon",
    "judge_injection_adversarial",
]

regex_res = {cat: {"total": 0, "intercepted": 0, "allowed": 0} for cat in cats}
regex_times = []

allowlist_res = {cat: {"total": 0, "intercepted": 0, "allowed": 0} for cat in cats}
allowlist_times = []

for c in cases:
    cat = c.family
    
    # 1. Regex
    t0 = time.perf_counter()
    txt = (c.page_state.visible_text or "") + " " + (c.page_state.raw_html or "") + " " + (c.proposed_action.source_text or "") + " " + (c.proposed_action.value or "") + " " + (c.proposed_action.target or "")
    hit = bool(TAXONOMY_REGEX.search(txt))
    regex_times.append((time.perf_counter() - t0) * 1e6) # in microseconds
    regex_res[cat]["total"] += 1
    if hit:
        regex_res[cat]["intercepted"] += 1
    else:
        regex_res[cat]["allowed"] += 1

    # 2. Tool Allowlist
    t0 = time.perf_counter()
    dom = c.domain
    act_type = c.proposed_action.action_type.upper()
    target = c.proposed_action.target
    m = manifests.get(dom, {})
    allowed_acts = m.get("allowed_actions", set())
    domain_allowlist = DOMAIN_ALLOWLISTS.get(dom, set())

    al_allowed = False
    if act_type == "NAVIGATE":
        target_lower = target.lower()
        if any(h in target_lower for h in domain_allowlist) or target.startswith("/"):
            al_allowed = True
    else:
        if (act_type, target.lower()) in allowed_acts or ("*", target.lower()) in allowed_acts:
            al_allowed = True
    allowlist_times.append((time.perf_counter() - t0) * 1e6) # in microseconds
    allowlist_res[cat]["total"] += 1
    if not al_allowed:
        allowlist_res[cat]["intercepted"] += 1
    else:
        allowlist_res[cat]["allowed"] += 1

print("=" * 80)
print("REGEX-ONLY FILTER ON DEV_HARD_60")
print("=" * 80)
for cat in cats:
    d = regex_res[cat]
    is_atk = (cat != "legitimate_unmapped_action")
    print(f"  {cat:<35}: intercepted={d['intercepted']:>2}/{d['total']} | {'Recall' if is_atk else 'Over-block'}={d['intercepted']/d['total']*100:5.1f}%")

print(f"\nRegex latency: median={sorted(regex_times)[len(regex_times)//2]:.1f} us, p95={sorted(regex_times)[int(len(regex_times)*0.95)]:.1f} us")

print("\n" + "=" * 80)
print("TOOL-ALLOWLIST GATE ON DEV_HARD_60")
print("=" * 80)
for cat in cats:
    d = allowlist_res[cat]
    is_atk = (cat != "legitimate_unmapped_action")
    print(f"  {cat:<35}: intercepted={d['intercepted']:>2}/{d['total']} | {'Recall' if is_atk else 'Over-block'}={d['intercepted']/d['total']*100:5.1f}%")

print(f"\nTool-Allowlist latency: median={sorted(allowlist_times)[len(allowlist_times)//2]:.2f} us, p95={sorted(allowlist_times)[int(len(allowlist_times)*0.95)]:.2f} us")

