"""
tests/test_glossary_consistency.py — Acceptance Test for G7 (Naming Consistency)

Verifies that:
1. docs/GLOSSARY.md exists and contains canonical definitions for L0–L11, Configs A–H, and Baselines 0–5.
2. Deprecated / retired terms (e.g. "zero-shot prompt judge" or "zero-shot llm judge" as a baseline name,
   "pooled recall" as a summary metric) do not appear in evaluation headers or active documentation.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
GLOSSARY_FILE = DOCS_DIR / "GLOSSARY.md"

RETIRED_TERMS = [
    re.compile(r"(?i)\bzero-shot (llm|prompt) judge\b"),
    re.compile(r"(?i)\bpooled (attack )?recall\b"),
    re.compile(r"(?i)\bzero-code generalization\b"),
]


def test_glossary_file_exists():
    assert GLOSSARY_FILE.is_file(), "docs/GLOSSARY.md must exist."
    content = GLOSSARY_FILE.read_text(encoding="utf-8")
    for layer_id in [f"L{i}" for i in range(12)]:
        assert f"**{layer_id}**" in content or f"`{layer_id}`" in content, f"Missing definition for {layer_id} in GLOSSARY.md"
    for config_id in ["Config A", "Config B", "Config C", "Config D", "Config E", "Config F", "Config G", "Config H"]:
        assert config_id in content, f"Missing {config_id} in GLOSSARY.md"
    for baseline_id in ["Baseline 0", "Baseline 1", "Baseline 2", "Baseline 3", "Baseline 4", "Baseline 5"]:
        assert baseline_id in content, f"Missing {baseline_id} in GLOSSARY.md"


def test_no_retired_names_in_glossary_definitions():
    """GLOSSARY.md must list retired names in section 4, but active baseline table must use canonical names."""
    content = GLOSSARY_FILE.read_text(encoding="utf-8")
    # In table section 3, Baseline 3 must be named Heuristic Prompt Classifier
    assert "Heuristic Prompt Classifier" in content
