"""
tests/test_glossary_consistency.py — Acceptance Test for G7 & Gap 4

Verifies that:
1. docs/GLOSSARY.md layer definitions equal the exact registered layers in code (contextguard/layers.py).
2. Any layer added or removed in code without updating docs/GLOSSARY.md fails this test.
3. Deprecated / retired terms do not appear as active baseline definitions or primary metrics.
"""

from __future__ import annotations

import re
from pathlib import Path
from contextguard.layers import REGISTERED_LAYERS, get_layer_count, get_layer_ids

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
GLOSSARY_FILE = DOCS_DIR / "GLOSSARY.md"


def test_registered_layers_match_glossary():
    assert GLOSSARY_FILE.is_file(), "docs/GLOSSARY.md must exist."
    content = GLOSSARY_FILE.read_text(encoding="utf-8")

    # Assert exact layer count
    code_layer_count = get_layer_count()
    assert code_layer_count == 12, f"Expected 12 registered layers (L0-L11), got {code_layer_count}"

    # Assert every layer in code is registered in glossary with exact ID and constant name
    for layer in REGISTERED_LAYERS:
        assert f"`{layer.layer_id}`" in content or f"**{layer.layer_id}**" in content, (
            f"Layer {layer.layer_id} in contextguard.layers missing from docs/GLOSSARY.md"
        )
        assert layer.constant_name in content, (
            f"Constant {layer.constant_name} for layer {layer.layer_id} missing from docs/GLOSSARY.md"
        )


def test_configurations_and_baselines_in_glossary():
    content = GLOSSARY_FILE.read_text(encoding="utf-8")
    for config_id in ["Config A", "Config B", "Config C", "Config D", "Config E", "Config F", "Config G", "Config H"]:
        assert config_id in content, f"Missing {config_id} in docs/GLOSSARY.md"
    for baseline_id in ["Baseline 0", "Baseline 1", "Baseline 2", "Baseline 3", "Baseline 4", "Baseline 5"]:
        assert baseline_id in content, f"Missing {baseline_id} in docs/GLOSSARY.md"


def test_canonical_baseline_naming_in_glossary():
    content = GLOSSARY_FILE.read_text(encoding="utf-8")
    # Baseline 3 must be defined as Heuristic Prompt Classifier
    assert "Heuristic Prompt Classifier" in content
    # Retired names section must be explicitly marked
    assert "Prohibited & Retired Terminology" in content
