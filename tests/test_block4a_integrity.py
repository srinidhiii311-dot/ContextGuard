"""
tests/test_block4a_integrity.py — Integrity Features & Concurrency Tests (Block 4a)

Tests:
1. Audit log tamper detection: editing one line, deleting one line, or reordering lines
   is detected by verify_audit_log(path) with the exact broken index.
2. Intent tamper detection: modifying intent produces Decision.BLOCK with reason INTENT_TAMPERED
   and writes an audit entry.
3. 50-session race test: asserting 50 concurrent sessions match sequential run decisions exactly
   and that every check() call produces exactly one audit entry with an unbroken hash chain.
4. Early-return allowed_action_types block: verifies early return writes to the audit log.
"""

from __future__ import annotations

import concurrent.futures
import json
from pathlib import Path
import pytest

from contextguard.audit_log import (
    AuditVerifyResult,
    GENESIS,
    JsonlAuditLog,
    get_audit_logger,
    verify_audit_log,
)
from contextguard.gate import ContextGuardGate, Decision, ProposedAction, TrustedIntent
from gateway.loader import Gateway
from harness.concurrency_bench import load_benchmark_cases


def test_audit_log_tamper_edit_detection(tmp_path):
    """Verifies that editing any audit entry is caught by verify_audit_log with the exact broken index."""
    log_file = tmp_path / "audit_edit.jsonl"
    logger = JsonlAuditLog(log_file)

    # 1. Write 10 valid entries
    for i in range(10):
        logger.append({
            "task_id": f"task_{i}",
            "step_number": i + 1,
            "action": {"type": "CLICK", "target": f"#btn_{i}"},
            "decision": "ALLOW",
            "reason": "Compliant action",
            "risk_score": 10,
        })

    # Initial check must pass
    initial_verify = verify_audit_log(log_file)
    assert initial_verify.ok is True
    assert initial_verify.checked_count == 10
    assert initial_verify.broken_index is None

    # 2. Tamper: edit entry at index 4 (change decision and reason)
    lines = []
    with open(log_file, "r", encoding="utf-8") as f:
        lines = [json.loads(l) for l in f if l.strip()]

    lines[4]["decision"] = "BLOCK"
    lines[4]["reason"] = "Tampered reason by attacker"

    with open(log_file, "w", encoding="utf-8") as f:
        for entry in lines:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    # Verify must detect tamper at index 4
    tampered_verify = verify_audit_log(log_file)
    assert tampered_verify.ok is False
    assert tampered_verify.broken_index == 4
    assert "entry_hash mismatch" in tampered_verify.reason


def test_audit_log_tamper_delete_and_reorder_detection(tmp_path):
    """Verifies that deleting or reordering lines breaks hash continuity and is detected."""
    log_file = tmp_path / "audit_del_reorder.jsonl"
    logger = JsonlAuditLog(log_file)

    for i in range(8):
        logger.append({
            "task_id": f"task_{i}",
            "step_number": i + 1,
            "action": {"type": "NAVIGATE", "target": f"http://site/page_{i}"},
            "decision": "ALLOW",
            "reason": "OK",
        })

    # 1. Deletion test: delete line at index 3
    with open(log_file, "r", encoding="utf-8") as f:
        entries = [json.loads(l) for l in f if l.strip()]

    deleted_entries = entries[:3] + entries[4:]
    with open(log_file, "w", encoding="utf-8") as f:
        for entry in deleted_entries:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    res_del = verify_audit_log(log_file)
    assert res_del.ok is False
    assert res_del.broken_index == 3
    assert "prev_hash mismatch" in res_del.reason

    # 2. Reordering test on a fresh log: swap index 2 and index 3
    log_reorder = tmp_path / "audit_reorder.jsonl"
    logger_ro = JsonlAuditLog(log_reorder)
    for i in range(6):
        logger_ro.append({"task_id": f"t_{i}", "step_number": i, "action": {"type": "CLICK", "target": f"#t_{i}"}, "decision": "ALLOW", "reason": "OK"})

    with open(log_reorder, "r", encoding="utf-8") as f:
        ro_entries = [json.loads(l) for l in f if l.strip()]

    ro_entries[2], ro_entries[3] = ro_entries[3], ro_entries[2]
    with open(log_reorder, "w", encoding="utf-8") as f:
        for entry in ro_entries:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    res_ro = verify_audit_log(log_reorder)
    assert res_ro.ok is False
    assert res_ro.broken_index == 2
    assert "prev_hash mismatch" in res_ro.reason


def test_intent_tamper_detection(tmp_path):
    """
    Verifies locked intent security:
    1. Normal intent passes.
    2. Any modified intent produces Decision.BLOCK with reason INTENT_TAMPERED.
    3. The tampered block decision is logged to the audit log.
    """
    audit_file = tmp_path / "intent_tamper_audit.jsonl"
    intent = TrustedIntent(
        origin="Chennai",
        destination="Delhi",
        cabin_class="Economy",
        passenger_count=1,
    )

    gw = Gateway.from_domain("flight", trusted_intent=intent, audit_log_path=audit_file)
    gate = gw.gate
    assert gate is not None

    # Step 1: Legitimate check passes
    act1 = ProposedAction(
        action_type="TYPE",
        target="#from",
        value="Chennai",
        page_url="http://127.0.0.1:8000/",
    )
    res1 = gw.check(act1, current_dom_text="Flight search page")
    assert res1.decision == Decision.ALLOW

    # Step 2: Adversary modifies intent (e.g. tampering destination to Mumbai)
    object.__setattr__(gate.trusted_intent, "destination", "Mumbai")

    act2 = ProposedAction(
        action_type="TYPE",
        target="#to",
        value="Mumbai",
        page_url="http://127.0.0.1:8000/",
    )
    res2 = gw.check(act2, current_dom_text="Flight search page")

    # Step 3: Must produce BLOCK with reason INTENT_TAMPERED
    assert res2.decision == Decision.BLOCK
    assert "INTENT_TAMPERED" in res2.reason

    # Step 4: Verify audit log recorded both decisions
    verify_res = verify_audit_log(audit_file)
    assert verify_res.ok is True
    assert verify_res.checked_count == 2

    with open(audit_file, "r", encoding="utf-8") as f:
        logged = [json.loads(l) for l in f if l.strip()]

    assert logged[0]["decision"] == "ALLOW"
    assert logged[1]["decision"] == "BLOCK"
    assert "INTENT_TAMPERED" in logged[1]["reason"]


def test_allowed_action_types_early_return_audit_entry(tmp_path):
    """Verifies that early-return allowed_action_types block is written to the audit log."""
    audit_file = tmp_path / "early_return_audit.jsonl"
    intent = TrustedIntent(extra_fields={"amount": "100.00"})
    gw = Gateway.from_domain("banking", trusted_intent=intent, audit_log_path=audit_file)

    # Disallowed action type
    act = ProposedAction(
        action_type="EXECUTE_RAW_SCRIPT",
        target="#script-eval",
        value="window.location='http://evil.com'",
        page_url="http://127.0.0.1:8001/transfer",
    )
    res = gw.check(act, current_dom_text="Transfer page")
    assert res.decision == Decision.BLOCK
    assert "not permitted under domain policy" in res.reason

    # Verify audit entry was logged
    verify_res = verify_audit_log(audit_file)
    assert verify_res.ok is True
    assert verify_res.checked_count == 1

    with open(audit_file, "r", encoding="utf-8") as f:
        entry = json.loads(f.readline())
    assert entry["decision"] == "BLOCK"
    assert "not permitted under domain policy" in entry["reason"]
    assert entry["action"]["type"] == "EXECUTE_RAW_SCRIPT"


def test_50_session_race_condition_and_exact_audit_completeness(tmp_path):
    """
    50-session race test:
    - Runs 50 sessions in parallel over benign and attack cases.
    - Asserts parallel decisions match sequential baseline 100%.
    - Asserts that every check() call produced EXACTLY one audit entry.
    - Asserts the audit log hash chain remains unbroken under concurrent execution.
    """
    cases = load_benchmark_cases(limit=50)
    assert len(cases) == 50

    # 1. Sequential run baseline
    seq_decisions = {}
    for idx, c in enumerate(cases):
        gw_seq = Gateway.from_domain(c.domain, trusted_intent=TrustedIntent(extra_fields=dict(c.locked_intent)))
        p_act = ProposedAction(
            action_type=c.proposed_action.action_type,
            target=c.proposed_action.target,
            value=c.proposed_action.value,
            page_url=c.proposed_action.page_url,
            raw_html=c.page_state.raw_html,
        )
        r = gw_seq.check(p_act, current_dom_text=c.page_state.visible_text)
        seq_decisions[c.case_id] = r.decision.value

    # 2. Concurrent 50-session run pointing to a single shared audit log
    race_audit = tmp_path / "shared_race_audit.jsonl"

    def run_concurrent_case(case_and_idx):
        idx, case = case_and_idx
        sess_id = f"session_race_{idx}"
        intent = TrustedIntent(extra_fields=dict(case.locked_intent))
        gw = Gateway.from_domain(
            case.domain,
            trusted_intent=intent,
            task_id=sess_id,
            audit_log_path=race_audit,
        )
        p_act = ProposedAction(
            action_type=case.proposed_action.action_type,
            target=case.proposed_action.target,
            value=case.proposed_action.value,
            page_url=case.proposed_action.page_url,
            raw_html=case.page_state.raw_html,
            session_id=sess_id,
            task_id=sess_id,
        )
        res = gw.check(p_act, current_dom_text=case.page_state.visible_text)
        return case.case_id, res.decision.value

    par_decisions = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(run_concurrent_case, (i, c)) for i, c in enumerate(cases)]
        for fut in concurrent.futures.as_completed(futures):
            cid, dec = fut.result()
            par_decisions[cid] = dec

    # Assert 1: Decisions match sequential run 100%
    assert len(par_decisions) == len(seq_decisions) == 50
    mismatches = []
    for cid, exp_dec in seq_decisions.items():
        actual_dec = par_decisions[cid]
        if actual_dec != exp_dec:
            mismatches.append(f"{cid}: expected {exp_dec}, got {actual_dec}")
    assert not mismatches, f"Concurrency decisions diverged: {mismatches}"

    # Assert 2: Exactly one audit entry per check() call
    with open(race_audit, "r", encoding="utf-8") as f:
        audit_lines = [l for l in f if l.strip()]
    assert len(audit_lines) == 50, f"Expected exactly 50 audit entries, found {len(audit_lines)}"

    # Assert 3: Hash chain integrity under 50-session concurrent writes
    audit_verify = verify_audit_log(race_audit)
    assert audit_verify.ok is True, f"Audit hash chain broken under concurrency: {audit_verify.reason}"
    assert audit_verify.checked_count == 50


def test_audit_log_tail_truncation_detected_by_anchor(tmp_path):
    """
    Verifies that tail truncation (which an unanchored hash chain cannot detect)
    is caught by verify_audit_log using the HMAC-signed external anchor.
    """
    log_file = tmp_path / "audit_trunc.jsonl"
    logger = JsonlAuditLog(log_file)
    for i in range(10):
        logger.append({"task_id": f"t_{i}", "action": {"type": "CLICK"}, "decision": "ALLOW", "reason": "OK"})

    # Intact verify passes
    initial_res = verify_audit_log(log_file)
    assert initial_res.ok is True
    assert initial_res.checked_count == 10

    # Truncate tail (keep first 6 entries, drop last 4)
    with open(log_file, "r", encoding="utf-8") as f:
        lines = [l for l in f if l.strip()]
    with open(log_file, "w", encoding="utf-8") as f:
        f.writelines(lines[:6])

    # verify_audit_log must catch tail truncation via the external anchor!
    trunc_res = verify_audit_log(log_file)
    assert trunc_res.ok is False
    assert trunc_res.broken_index == 6
    assert "tail truncated" in trunc_res.reason


def test_audit_log_forged_anchor_hmac_rejected(tmp_path):
    """Verifies that an attacker rewriting the anchor file without the gateway key is rejected."""
    log_file = tmp_path / "audit_forged.jsonl"
    logger = JsonlAuditLog(log_file)
    for i in range(5):
        logger.append({"task_id": f"t_{i}", "action": {"type": "CLICK"}, "decision": "ALLOW", "reason": "OK"})

    anchor_file = tmp_path / "audit_forged_anchor.jsonl"
    assert anchor_file.exists()

    # Tamper with anchor HMAC signature
    with open(anchor_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"ts": 12345.0, "head_hash": "deadbeef" * 8, "row_count": 5, "hmac": "badhmac" * 8}) + "\n")

    res = verify_audit_log(log_file)
    assert res.ok is False
    assert "anchor HMAC signature invalid" in res.reason


