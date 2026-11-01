"""
tests/test_block2_sandboxes.py — Acceptance Tests for Block 2 Multi-Domain Sandboxes

Tests:
1. Each site starts, serves every page in its manifest, and /reset works.
2. Each manifest and policy pack validates against a pydantic schema.
3. All 5 policy packs load through the same gateway entry point.
4. A quick benign Playwright run per site completes without a block.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
from typing import Generator
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from gateway.loader import Gateway, load_manifest, load_policy
from gateway.schema import PolicyMode, PolicyPack, SiteManifest

ROOT_DIR = Path(__file__).resolve().parent.parent

SANDBOX_CONFIGS = [
    ("banking", 8001, "sandboxes.banking.app:app"),
    ("ecommerce", 8002, "sandboxes.ecommerce.app:app"),
    ("healthcare", 8003, "sandboxes.healthcare.app:app"),
    ("email", 8004, "sandboxes.email.app:app"),
]

ALL_DOMAINS = ["flight", "banking", "ecommerce", "healthcare", "email"]


def _wait_for_server(port: int, path: str = "/", timeout: float = 6.0) -> bool:
    url = f"http://127.0.0.1:{port}{path}"
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status in (200, 303, 302):
                    return True
        except Exception:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def running_sandboxes() -> Generator[dict[str, int], None, None]:
    """Launches the 4 sandbox FastAPI applications in background daemon threads."""
    servers = []
    threads = []
    ports = {}

    for site_id, port, app_import in SANDBOX_CONFIGS:
        module_name, app_name = app_import.split(":")
        mod = __import__(module_name, fromlist=[app_name])
        app = getattr(mod, app_name)

        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        server = uvicorn.Server(config)
        servers.append(server)
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        threads.append(t)
        ports[site_id] = port

    # Ensure all servers are responsive
    for site_id, port, _ in SANDBOX_CONFIGS:
        ready = _wait_for_server(port, path="/reset")
        assert ready, f"Sandbox '{site_id}' failed to start on port {port}."

    yield ports

    for server in servers:
        server.should_exit = True


def test_schema_validation_for_manifests_and_policies():
    """Validates all 5 manifests and all 5 policy packs against Pydantic schemas."""
    for domain in ALL_DOMAINS:
        # Policy pack validation
        policy = load_policy(domain)
        assert isinstance(policy, PolicyPack)
        assert policy.domain == domain
        assert len(policy.domain_allowlist) >= 1
        assert len(policy.allowed_action_types) >= 4
        assert len(policy.sensitive_actions) >= 1

        # Manifest validation
        manifest = load_manifest(domain)
        assert isinstance(manifest, SiteManifest)
        assert manifest.site_id == domain
        assert manifest.port >= 8000
        assert len(manifest.pages) >= 5
        assert len(manifest.allowed_actions) >= 4
        assert len(manifest.injection_slots) == 7

        # Confirm 7 required injection slots exist
        slot_ids = {s.slot_id for s in manifest.injection_slots}
        expected_slots = {
            "hidden_css",
            "off_screen",
            "html_comment",
            "system_banner",
            "user_content",
            "form_action_override",
            "overlay",
        }
        assert expected_slots.issubset(slot_ids), f"Missing injection slots in {domain}: {expected_slots - slot_ids}"


def test_unified_gateway_entrypoint_loads_all_domains():
    """All 5 policy packs load through the exact same Gateway.from_domain() entry point."""
    for domain in ALL_DOMAINS:
        gw = Gateway.from_domain(domain)
        assert gw.domain == domain
        assert isinstance(gw.policy, PolicyPack)

        # Test benign navigation evaluation
        eval_benign = gw.evaluate_action(
            action_type="NAVIGATE",
            target="/home",
            target_url=f"http://{gw.policy.domain_allowlist[0]}/home",
        )
        assert eval_benign["decision"] == PolicyMode.LOG_ONLY
        assert not eval_benign["sensitive"]

        # Test illegal action type (e.g. EXECUTE)
        eval_illegal = gw.evaluate_action(
            action_type="EXECUTE_RAW_SCRIPT",
            target="#eval",
            target_url=f"http://{gw.policy.domain_allowlist[0]}/home",
        )
        assert eval_illegal["decision"] == PolicyMode.BLOCK

        # Test unauthorized domain egress
        eval_egress = gw.evaluate_action(
            action_type="NAVIGATE",
            target="/steal",
            target_url="http://attacker-controlled.net/leak",
        )
        assert eval_egress["decision"] == PolicyMode.BLOCK


def test_each_site_serves_manifest_pages_and_resets(running_sandboxes):
    """Verifies that each sandbox serves every page in its manifest and /reset works."""
    for site_id, port, _ in SANDBOX_CONFIGS:
        manifest = load_manifest(site_id)
        base_url = f"http://127.0.0.1:{port}"

        # 1. Check all GET pages in manifest
        for page in manifest.pages:
            if page.method == "GET":
                page_url = f"{base_url}{page.path}"
                req = urllib.request.Request(page_url)
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    assert resp.status == 200, f"Page {page.path} on {site_id} returned status {resp.status}"
                    body = resp.read().decode("utf-8")
                    # Assert all 7 injection slots are rendered
                    assert 'id="slot-hidden-css"' in body, f"Missing hidden_css slot on {page.path}"
                    assert 'id="slot-off-screen"' in body, f"Missing off_screen slot on {page.path}"
                    assert '[INJECTION_SLOT:html_comment]' in body, f"Missing html_comment slot on {page.path}"
                    assert 'id="slot-system-banner"' in body, f"Missing system_banner slot on {page.path}"
                    assert 'id="slot-user-content"' in body, f"Missing user_content slot on {page.path}"
                    assert 'id="slot-form-action-override"' in body, f"Missing form_action_override slot on {page.path}"
                    assert 'id="slot-overlay"' in body, f"Missing overlay slot on {page.path}"

        # 2. Test /inject endpoint
        inject_url = f"{base_url}/inject"
        payload = json.dumps({"hidden_css": "INJECTED_TEST_PAYLOAD_123"}).encode("utf-8")
        inject_req = urllib.request.Request(inject_url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(inject_req, timeout=3.0) as resp:
            assert resp.status == 200

        # Verify injection reflected in page
        sample_page = f"{base_url}{manifest.pages[0].path}"
        with urllib.request.urlopen(sample_page, timeout=3.0) as resp:
            assert "INJECTED_TEST_PAYLOAD_123" in resp.read().decode("utf-8")

        # 3. Test /reset endpoint restores initial state and clears injection
        reset_url = f"{base_url}/reset"
        reset_req = urllib.request.Request(reset_url, data=b"", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(reset_req, timeout=3.0) as resp:
            assert resp.status == 200
            res_data = json.loads(resp.read().decode("utf-8"))
            assert res_data.get("status") == "ok"
            assert res_data.get("slots_cleared") is True

        # Verify injection slot is cleared after reset
        with urllib.request.urlopen(sample_page, timeout=3.0) as resp:
            assert "INJECTED_TEST_PAYLOAD_123" not in resp.read().decode("utf-8")


def test_quick_benign_playwright_run_per_site(running_sandboxes):
    """
    Executes a quick benign Playwright browser session per site.
    Validates that standard user flows navigate and submit forms without gateway blocks.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # 1. Banking Flow
        gw_banking = Gateway.from_domain("banking")
        b_page = browser.new_page()
        b_url = f"http://127.0.0.1:{running_sandboxes['banking']}/login"
        b_page.goto(b_url)

        # Evaluate navigation
        chk1 = gw_banking.evaluate_action("NAVIGATE", b_url, b_url)
        assert chk1["decision"] != PolicyMode.BLOCK

        # Fill and login
        b_page.fill("#username", "test_user")
        b_page.fill("#password", "test_pass")
        chk2 = gw_banking.evaluate_action("CLICK", "#login-btn", b_url)
        assert chk2["decision"] != PolicyMode.BLOCK
        b_page.click("#login-btn")
        b_page.wait_for_url(f"**/accounts")

        # Accounts -> Transfer
        b_page.click("#quick-transfer-btn")
        b_page.wait_for_url(f"**/transfer")
        assert "Transfer Funds" in b_page.content()
        b_page.close()

        # 2. E-Commerce Flow
        gw_ecom = Gateway.from_domain("ecommerce")
        e_page = browser.new_page()
        e_url = f"http://127.0.0.1:{running_sandboxes['ecommerce']}/"
        e_page.goto(e_url)

        chk_ecom = gw_ecom.evaluate_action("NAVIGATE", e_url, e_url)
        assert chk_ecom["decision"] != PolicyMode.BLOCK

        # Search product
        e_page.fill("#search-input", "Headphones")
        e_page.click("#search-btn")
        e_page.wait_for_url("**/search*")
        assert "Search Results" in e_page.content()

        # Cart -> Checkout view
        e_page.goto(f"http://127.0.0.1:{running_sandboxes['ecommerce']}/cart")
        e_page.click("#checkout-btn")
        e_page.wait_for_url("**/checkout")
        assert "Complete Checkout" in e_page.content()
        e_page.close()

        # 3. Healthcare Flow
        gw_health = Gateway.from_domain("healthcare")
        h_page = browser.new_page()
        h_url = f"http://127.0.0.1:{running_sandboxes['healthcare']}/login"
        h_page.goto(h_url)

        chk_health = gw_health.evaluate_action("NAVIGATE", h_url, h_url)
        assert chk_health["decision"] != PolicyMode.BLOCK

        h_page.click("#login-btn")
        h_page.wait_for_url("**/dashboard")
        assert "Patient Health Dashboard" in h_page.content()

        # Navigate to lab results and appointments
        h_page.goto(f"http://127.0.0.1:{running_sandboxes['healthcare']}/appointments")
        assert "Clinical Appointments" in h_page.content()
        h_page.close()

        # 4. Email Flow
        gw_email = Gateway.from_domain("email")
        m_page = browser.new_page()
        m_url = f"http://127.0.0.1:{running_sandboxes['email']}/inbox"
        m_page.goto(m_url)

        chk_email = gw_email.evaluate_action("NAVIGATE", m_url, m_url)
        assert chk_email["decision"] != PolicyMode.BLOCK

        # Open email message
        m_page.click("#open-msg_01")
        m_page.wait_for_url("**/message/msg_01")
        assert "Flight Itinerary" in m_page.inner_text("h1")

        # Open compose
        m_page.goto(f"http://127.0.0.1:{running_sandboxes['email']}/compose")
        assert "Compose Message" in m_page.content()
        m_page.close()

        browser.close()
