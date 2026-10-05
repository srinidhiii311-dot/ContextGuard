#!/usr/bin/env python3
"""Run the FROZEN test set exactly once.

    python scripts/run_final_eval.py --final --adapter myproject.adapter:evaluate \
        --data eval_data/test_v1 --configs A_rules_only,D_full

Guards
- Refuses to run without --final.
- Refuses a second run (eval_results/.final_run_done) unless --allow-rerun, which is
  recorded in the output so the write-up can disclose it.
- Writes per-item decisions, summary JSON and paired McNemar counts between configs.

Adapter contract:  evaluate(item: dict, config: str) -> dict
  required key: "decision" (BLOCK | REQUIRE_CONFIRMATION | PAUSE_TASK | ALLOW_WITH_FLAG | ALLOW)
  optional keys: "score", "fired", "latency_ms"
Dataset files: *.yaml / *.yml / *.json holding a list (or {"items": [...]}) of items with
  at least {"id", "label": "attack"|"benign"} and optionally {"category"}.
"""
from __future__ import annotations

import argparse
import csv
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from stats import classify, paired_counts, summarize  # noqa: E402


def load_items(data_dir: Path):
    items = []
    for p in sorted(data_dir.glob("*")):
        if p.suffix in (".yaml", ".yml"):
            import yaml
            obj = yaml.safe_load(p.read_text(encoding="utf-8"))
        elif p.suffix == ".json":
            obj = json.loads(p.read_text(encoding="utf-8"))
        else:
            continue
        items.extend(obj["items"] if isinstance(obj, dict) and "items" in obj else obj or [])
    for it in items:
        if "id" not in it or it.get("label") not in ("attack", "benign"):
            raise ValueError(f"bad item (needs id and label attack|benign): {it!r}")
    ids = [i["id"] for i in items]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate item ids")
    return items


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", action="store_true", help="required: confirms this is the one final run")
    ap.add_argument("--allow-rerun", action="store_true")
    ap.add_argument("--adapter", required=True, help="module:function")
    ap.add_argument("--data", default="eval_data/test_v1")
    ap.add_argument("--configs", default="D_full")
    ap.add_argument("--out", default="eval_results/final_test_results.csv")
    a = ap.parse_args(argv)

    if not a.final:
        print("REFUSED: the frozen test set is run once, with --final, after every fix is tagged.")
        return 2
    out = Path(a.out)
    lock = out.parent / ".final_run_done"
    if lock.exists() and not a.allow_rerun:
        print(f"REFUSED: {lock} exists. The frozen set was already run. Use --allow-rerun and disclose it.")
        return 3
    mod, fn = a.adapter.split(":")
    sys.path.insert(0, str(Path.cwd()))
    evaluate = getattr(importlib.import_module(mod), fn)
    items = load_items(Path(a.data))
    configs = [c.strip() for c in a.configs.split(",") if c.strip()]

    out.parent.mkdir(parents=True, exist_ok=True)
    rows, by_cfg = [], {c: [] for c in configs}
    for c in configs:
        for it in items:
            r = evaluate(it, c)
            d = str(r["decision"])
            rows.append({"item_id": it["id"], "label": it["label"], "category": it.get("category", ""),
                         "config": c, "decision": d, "outcome": classify(d),
                         "score": r.get("score", ""), "fired": json.dumps(r.get("fired", "")),
                         "latency_ms": r.get("latency_ms", "")})
            by_cfg[c].append((it["label"], d, it["id"]))
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    summary = {c: summarize(by_cfg[c]) for c in configs}
    stops = {c: {i: classify(d) == "intercepted" for l, d, i in by_cfg[c] if l == "attack"} for c in configs}
    pairs = {f"{x}->{y}": paired_counts(stops[x], stops[y])
             for x, y in zip(configs, configs[1:])}
    cats = {}
    for r in rows:
        if r["label"] == "attack":
            k = (r["config"], r["category"] or "uncategorised")
            cats.setdefault(k, [0, 0])
            cats[k][1] += 1
            cats[k][0] += r["outcome"] == "intercepted"
    report = {"summary": summary, "paired": pairs, "rerun_disclosed": bool(lock.exists()),
              "per_category": {f"{c}|{cat}": f"{k}/{n}" for (c, cat), (k, n) in cats.items()}}
    (out.parent / "final_test_summary.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lock.write_text("final run completed\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
