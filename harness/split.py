"""
harness/split.py — Deterministic Attack Family Splitting & Tuning Isolation Guard (Block 1)

Assigns each attack family to 'dev' or 'test' deterministically using a fixed seed,
guaranteeing at least 2 attack families are held out exclusively for test.
Enforces the standing research rule: 'Never read test data in any tuning script'.
"""

from __future__ import annotations

import random
from typing import Any, Dict, Iterable, List, Literal, Mapping, Sequence, TypeVar, Union

T = TypeVar("T")

DEFAULT_ATTACK_FAMILIES = [
    "prompt_injection",
    "dom_manipulation",
    "hidden_content",
    "navigation_attack",
    "context_manipulation",
    "plan_integrity",
    "fee_tampering",
    "exfiltration",
]

DEFAULT_SEED = 42
MIN_TEST_FAMILIES = 2


class TestDataLeakError(PermissionError):
    """Raised when a tuning script or dev procedure attempts to access test split data."""
    pass


def assign_splits(
    families: Sequence[str] | None = None,
    test_count: int = 2,
    seed: int = DEFAULT_SEED,
) -> Dict[str, Literal["dev", "test"]]:
    """
    Deterministically assigns each attack family to 'dev' or 'test'.
    
    Guarantees:
    - At least 2 attack families are assigned to 'test'.
    - Deterministic across runs for a given seed (sorts families prior to shuffle).
    - Every family is assigned to exactly one split.
    """
    if families is None:
        family_list = list(DEFAULT_ATTACK_FAMILIES)
    else:
        family_list = list(families)

    unique_sorted = sorted(set(family_list))

    if test_count < MIN_TEST_FAMILIES:
        raise ValueError(
            f"test_count must be at least {MIN_TEST_FAMILIES} (got {test_count}). "
            f"At least {MIN_TEST_FAMILIES} attack families must be held out for test only."
        )

    if len(unique_sorted) < test_count + 1:
        raise ValueError(
            f"Cannot hold out {test_count} test families from a set of {len(unique_sorted)} families. "
            f"At least {test_count + 1} distinct families required."
        )

    rng = random.Random(seed)
    shuffled = unique_sorted.copy()
    rng.shuffle(shuffled)

    test_families = set(shuffled[:test_count])
    split_assignment: Dict[str, Literal["dev", "test"]] = {}

    for fam in unique_sorted:
        split_assignment[fam] = "test" if fam in test_families else "dev"

    return split_assignment


def get_family_split(
    family: str,
    families: Sequence[str] | None = None,
    test_count: int = 2,
    seed: int = DEFAULT_SEED,
) -> Literal["dev", "test"]:
    """Returns the split ('dev' or 'test') for a specific attack family."""
    assignments = assign_splits(families=families, test_count=test_count, seed=seed)
    if family not in assignments:
        raise KeyError(f"Family '{family}' is not in the assigned family set: {list(assignments.keys())}")
    return assignments[family]


def get_held_out_test_families(
    families: Sequence[str] | None = None,
    test_count: int = 2,
    seed: int = DEFAULT_SEED,
) -> List[str]:
    """Returns the list of families strictly held out for test only."""
    assignments = assign_splits(families=families, test_count=test_count, seed=seed)
    return sorted([fam for fam, split in assignments.items() if split == "test"])


def get_dev_families(
    families: Sequence[str] | None = None,
    test_count: int = 2,
    seed: int = DEFAULT_SEED,
) -> List[str]:
    """Returns the list of families available for development and tuning."""
    assignments = assign_splits(families=families, test_count=test_count, seed=seed)
    return sorted([fam for fam, split in assignments.items() if split == "dev"])


def guard_tuning_item(item: Any, split_attr: str = "split") -> None:
    """
    Enforces isolation: Raises TestDataLeakError if item belongs to the 'test' split.
    Supports strings, dicts, Pydantic models, or objects with attributes.
    """
    val = None
    if isinstance(item, str):
        val = item
    elif isinstance(item, Mapping):
        val = item.get(split_attr)
    elif hasattr(item, split_attr):
        val = getattr(item, split_attr)

    if val == "test":
        raise TestDataLeakError(
            f"DATA LEAKAGE DETECTED: Attempted to process item belonging to the 'test' split "
            f"in a tuning / dev script. Standing rule: Never read test data during development/tuning."
        )


def assert_dev_only(items: Iterable[Any], split_attr: str = "split") -> None:
    """
    Scans a collection and raises TestDataLeakError if ANY item has split == 'test'.
    """
    for idx, item in enumerate(items):
        try:
            guard_tuning_item(item, split_attr=split_attr)
        except TestDataLeakError as err:
            raise TestDataLeakError(f"Leakage at index {idx}: {err}") from err


def filter_for_tuning(items: Iterable[T], split_attr: str = "split") -> List[T]:
    """
    Filters a dataset to return ONLY dev-split items, safely preventing any test leakage.
    """
    dev_items: List[T] = []
    for item in items:
        val = None
        if isinstance(item, str):
            val = item
        elif isinstance(item, Mapping):
            val = item.get(split_attr)
        elif hasattr(item, split_attr):
            val = getattr(item, split_attr)

        if val == "test":
            continue
        dev_items.append(item)
    return dev_items

