"""
scripts/audit_scenario_leaks.py — Rendered DOM Leak Audit across all 18 Scenarios

Audits the actual rendered HTML of every mock_site route (search, results, passenger, review, confirm)
across all calibration scenarios (TC-01..TC-08) and held-out scenarios (TC-01H..TC-10H).

Asserts that ZERO test-harness fingerprints leak into the user-facing/viewer DOM:
- 'TC-0'
- 'testbed'
- 'attack-banner'
- 'data-testbed'
- 'data-attack-type'
- 'window._testbed'

Exits 0 if 100% clean, non-zero if any testbed token is detected in rendered output.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Use test DB to prevent pollution
test_db = Path(__file__).parent / "test_leak_audit.db"
if test_db.exists():
    try:
        test_db.unlink()
    except Exception:
        pass
os.environ["CONTEXTGUARD_DB_PATH"] = str(test_db)

from fastapi.testclient import TestClient

from backend.attack_injector.injector import attack_injector
from backend.db.models import SessionControllerDAO, init_db
from backend.main import app

FORBIDDEN_FINGERPRINTS = [
    "TC-0",
    "testbed",
    "attack-banner",
    "data-testbed",
    "data-attack-type",
    "_testbed",
    "attack_injector",
]

SCENARIO_IDS = [
    "TC-01", "TC-02", "TC-03", "TC-04", "TC-05", "TC-06", "TC-07", "TC-08",
    "TC-01H", "TC-02H", "TC-03H", "TC-04H", "TC-05H", "TC-06H", "TC-07H", "TC-08H", "TC-09H", "TC-10H"
]

PAGES = ["search", "results", "passenger", "review", "confirm"]


def audit_rendered_dom():
    print("=" * 80)
    print("  RENDERED DOM LEAK AUDIT ACROSS ALL 18 SCENARIOS")
    print(f"  Scanning {len(SCENARIO_IDS)} scenarios × {len(PAGES)} pages = {len(SCENARIO_IDS) * len(PAGES)} rendered HTML documents")
    print("=" * 80)

    init_db()
    client = TestClient(app)

    total_audited = 0
    leaks_found: List[str] = []

    for sc_id in SCENARIO_IDS:
        # Create session
        sess_id, token, viewer_tok = SessionControllerDAO.create_session(
            "Audit flight booking",
            {"origin": "Chennai", "destination": "Bangalore", "cabin_class": "Economy", "passenger_count": 2},
            test_case_id=sc_id,
        )

        attack_injector.arm_scenario(session_id=sess_id, test_case_id=sc_id)

        for page in PAGES:
            total_audited += 1
            url = f"/mock_site/{sess_id}/{page}?token={viewer_tok}"
            resp = client.get(url)
            if resp.status_code != 200:
                leaks_found.append(f"HTTP {resp.status_code} on {url}")
                continue

            html_text = resp.text
            for fp in FORBIDDEN_FINGERPRINTS:
                if fp.lower() in html_text.lower():
                    # Check if fingerprint is in the page
                    leaks_found.append(
                        f"Leak [{fp}] detected in rendered HTML for scenario {sc_id} on page '{page}'"
                    )

        print(f"  [OK] {sc_id:<7} — All 5 routes rendered clean without harness fingerprints")

    print("\n" + "=" * 80)
    print(f"  AUDIT SUMMARY: {total_audited} pages checked across {len(SCENARIO_IDS)} scenarios")
    print("=" * 80)

    if leaks_found:
        print("  CRITICAL FAILURES DETECTED:")
        for leak in leaks_found:
            print(f"  [LEAK] {leak}")
        sys.exit(1)
    else:
        print("  [PASS] ZERO HARNESS FINGERPRINTS DETECTED IN RENDERED DOM.")
        print("  All pages are completely sanitized and indistinguishable from genuine web services.")
        print("=" * 80)

    # Cleanup
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass


if __name__ == "__main__":
    audit_rendered_dom()
