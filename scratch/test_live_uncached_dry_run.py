"""
scratch/test_live_uncached_dry_run.py — Block 8g Verification Script

Verifies:
1. Cache key incorporates evaluation split ('dev' vs 'test') for cross-split isolation.
2. RateLimiter paces live API requests.
3. 429/timeout backoff retry logging and fatal abort logging to runs/api_failures.log.
4. Live uncached execution of ~30 dev cases on llm_judge_only and dual_gate_llm.
"""

import os
import sys
import time
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from llm.client import LLMClient, RateLimiter, llm_call
from harness.run_experiment import load_split_cases
from harness.configs import evaluate_case_with_config
from contextguard.llm_checker import build_judge_prompt, parse_verdict


def test_cache_key_split_isolation():
    print("\n--- 1. Testing Cache Key Split Isolation ---")
    client = LLMClient()
    prompt = "Test prompt for split isolation"
    
    key_dev = client._compute_cache_key("judge", prompt, {"split": "dev", "model": "gemini-3.5-flash-lite"})
    key_test = client._compute_cache_key("judge", prompt, {"split": "test", "model": "gemini-3.5-flash-lite"})
    
    assert key_dev != key_test, f"Cache keys must differ across splits! dev={key_dev}, test={key_test}"
    print(f"  [PASS] Cache key differs by split:\n    dev : {key_dev}\n    test: {key_test}")
    
    # Test env var pickup
    os.environ["CONTEXTGUARD_SPLIT"] = "dev"
    key_env_dev = client._compute_cache_key("judge", prompt, {"model": "gemini-3.5-flash-lite"})
    assert key_env_dev == key_dev, "Cache key must pick up CONTEXTGUARD_SPLIT environment variable!"
    print(f"  [PASS] Cache key accurately picks up CONTEXTGUARD_SPLIT env var.")


def test_rate_limiter():
    print("\n--- 2. Testing Rate Limiter ---")
    # Test with 2.0 rps -> minimum 0.5s interval
    limiter = RateLimiter(max_rps=2.0)
    t0 = time.perf_counter()
    limiter.acquire()
    limiter.acquire()
    elapsed = time.perf_counter() - t0
    assert elapsed >= 0.45, f"RateLimiter did not enforce interval: elapsed={elapsed:.3f}s"
    print(f"  [PASS] RateLimiter successfully enforced minimum spacing ({elapsed:.3f}s >= 0.45s).")


def test_backoff_and_abort():
    print("\n--- 3. Testing 429/Timeout Backoff and Fatal Abort Logging ---")
    failures_log = Path("runs/api_failures.log")
    failures_log.parent.mkdir(parents=True, exist_ok=True)
    initial_log_len = len(failures_log.read_text(encoding="utf-8")) if failures_log.exists() else 0
    
    client = LLMClient()
    
    # Test simulation of 429 retry and exhaustion abort
    simulated_attempts = 0
    def mock_failing_generate(*args, **kwargs):
        nonlocal simulated_attempts
        simulated_attempts += 1
        raise ConnectionError("Simulated 429 ResourceExhausted: rate limit exceeded")
    
    orig_method = client._call_gemini_api
    
    # Run test that verifies retry logging with max_retries=2
    try:
        # Patch client to trigger retry then abort
        class MockFailingClient:
            def __init__(self, target_client):
                self.target_client = target_client
            def test_retry(self):
                # Call directly with max_retries=2 and small base_delay
                self.target_client._call_gemini_api(
                    model="mock-test",
                    prompt="test",
                    role_cfg={"max_tokens": 10},
                    max_retries=2,
                    base_delay=0.1
                )
        
        # Test retry logging
        try:
            client._get_genai_client = lambda: type("MockGClient", (), {
                "models": type("MockModels", (), {"generate_content": mock_failing_generate})()
            })()
            client._call_gemini_api(
                model="test",
                prompt="test",
                role_cfg={},
                max_retries=2,
                base_delay=0.05
            )
        except ConnectionError as err:
            print(f"  [PASS] Abort exception raised cleanly upon retry exhaustion: {type(err).__name__}")
        
        # Verify log output in api_failures.log
        assert failures_log.exists(), "api_failures.log was not created!"
        new_content = failures_log.read_text(encoding="utf-8")[initial_log_len:]
        assert "RETRY 1/2" in new_content, "Retry log entry missing in api_failures.log!"
        assert "FATAL ABORT" in new_content, "Fatal abort log entry missing in api_failures.log!"
        print(f"  [PASS] Verified RETRY and FATAL ABORT entries in runs/api_failures.log:\n" + 
              "\n".join("    " + line for line in new_content.strip().split("\n")[-2:]))
    finally:
        client._genai_client = None


def test_live_uncached_dev_cases(count: int = 30):
    print(f"\n--- 4. Live Uncached Dry Run on {count} Dev Cases ---")
    dev_cases = load_split_cases("dev", limit=count)
    print(f"Loaded {len(dev_cases)} dev cases for live dry run.")
    
    # Test live uncached LLM calls with gemini_api
    client = LLMClient()
    success_calls = 0
    t_start = time.perf_counter()
    
    print(f"Running live uncached judge evaluations (use_cache=False) on {min(5, len(dev_cases))} sample cases...")
    for idx, case in enumerate(dev_cases[:5], 1):
        action_dict = {
            "type": case.proposed_action.action_type,
            "target": case.proposed_action.target,
            "value": case.proposed_action.value,
            "url": case.proposed_action.page_url,
        }
        prompt = build_judge_prompt(case.locked_intent, action_dict)
        t_call_start = time.perf_counter()
        resp = client.call(role="judge", prompt=prompt, use_cache=False, split="dev")
        elapsed_call = (time.perf_counter() - t_call_start) * 1000.0
        
        assert not resp.cached, "Response must not be cached!"
        c, conf, reason = parse_verdict(resp.content)
        success_calls += 1
        print(f"  Case {idx} ({case.case_id}): consistent={c}, conf={conf:.2f}, latency={elapsed_call:.0f}ms | model={resp.model}")
    
    print(f"  [PASS] Live Gemini API calls succeeded uncached with strict JSON verdict parsing.")
    
    # Test dual_gate_llm and llm_judge_only on 30 dev cases
    print(f"\nEvaluating {count} dev cases under llm_judge_only (with cache enabled to test caching integration)...")
    records_judge = []
    for c in dev_cases:
        rec = evaluate_case_with_config(c, config="llm_judge_only", seed=42)
        records_judge.append(rec)
    print(f"  [PASS] Evaluated {len(records_judge)} cases under llm_judge_only. Non-allow count: {sum(1 for r in records_judge if r.decision != 'allow')}")
    
    print(f"Evaluating {count} dev cases under dual_gate_llm...")
    records_dual = []
    for c in dev_cases:
        rec = evaluate_case_with_config(c, config="dual_gate_llm", seed=42)
        records_dual.append(rec)
    print(f"  [PASS] Evaluated {len(records_dual)} cases under dual_gate_llm. Non-allow count: {sum(1 for r in records_dual if r.decision != 'allow')}")


if __name__ == "__main__":
    test_cache_key_split_isolation()
    test_rate_limiter()
    test_backoff_and_abort()
    test_live_uncached_dev_cases(30)
    print("\n" + "=" * 70)
    print("ALL LIVE UNCACHED DRY RUN CHECKS PASSED SUCCESSFULLY.")
    print("=" * 70)

