"""
tests/test_url_trust.py — URL Trust & Evasion Robustness Benchmark (Block 6c)

Asserts that _is_trusted_navigation in ContextConsistencyVerifier enforces:
1. Scheme must be strictly http or https (case-insensitive).
2. Normalized hostname (with userinfo stripped, IDNA/punycode normalized, trailing dots stripped)
   must exactly match an entry in the trust boundary allowlist.
3. Port must match the configured allowlist entry port (or default 80/443).
4. Rejects evasions:
   - Userinfo trick (@)
   - Lookalike subdomains
   - Punycode & Cyrillic/homoglyph characters
   - Hex / octal / decimal IP representations
   - Trailing dots on untrusted domains or after port
   - Port mismatches
   - Protocol-relative URLs (//host)
   - javascript: and data: URIs
   - Percent-encoding tricks (%74%72%75..., %23, %40)
   - Open-redirect query parameters pointing to untrusted domains
   - Case manipulation (uppercase scheme and hostname)
"""

from __future__ import annotations

import pytest
from contextguard.consistency_checker import ContextConsistencyVerifier


@pytest.fixture
def verifier():
    """Instantiates verifier with a controlled trust boundary allowlist."""
    v = ContextConsistencyVerifier()
    v.trusted_hosts = [
        "127.0.0.1:8000",
        "localhost:8000",
        "trusted.com:8000",
        "api.trusted.com:443",
        "trusted.com",
    ]
    return v


# ---------------------------------------------------------------------------
# 1. Userinfo '@' Tricks (Must strip userinfo and reject attacker destinations)
# ---------------------------------------------------------------------------

def test_userinfo_attacker_host(verifier):
    """http://trusted.com@attacker.com must resolve to attacker.com and be rejected."""
    assert verifier._is_trusted_navigation("http://trusted.com@attacker.com") is False


def test_userinfo_with_credentials(verifier):
    """http://user:password@trusted.com@evil.com must be rejected."""
    assert verifier._is_trusted_navigation("http://user:password@trusted.com@evil.com") is False


def test_userinfo_with_port_confusion(verifier):
    """http://127.0.0.1:8000@malicious.org must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000@malicious.org/path") is False


def test_userinfo_percent_encoded_at(verifier):
    """http://trusted.com%40attacker.com must be rejected."""
    assert verifier._is_trusted_navigation("http://trusted.com%40attacker.com") is False


def test_userinfo_hash_at_trick(verifier):
    """http://127.0.0.1%23@attacker.com must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1%23@attacker.com") is False


# ---------------------------------------------------------------------------
# 2. Lookalike Subdomains (Must match full hostname, not substring)
# ---------------------------------------------------------------------------

def test_lookalike_subdomain_attacker_parent(verifier):
    """http://trusted.com.evil.com must be rejected."""
    assert verifier._is_trusted_navigation("http://trusted.com.evil.com") is False


def test_lookalike_ip_subdomain(verifier):
    """http://127.0.0.1.attacker.com:8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1.attacker.com:8000") is False


def test_lookalike_hyphenated_domain(verifier):
    """http://evil-trusted.com:8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://evil-trusted.com:8000") is False


def test_lookalike_localhost_subdomain(verifier):
    """http://localhost.evil.com:8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://localhost.evil.com:8000") is False


# ---------------------------------------------------------------------------
# 3. Punycode and Homoglyphs (Non-ASCII & homoglyphs must not masquerade)
# ---------------------------------------------------------------------------

def test_punycode_lookalike_rejected(verifier):
    """xn--truted-1wa.com (punycode lookalike) must be rejected."""
    assert verifier._is_trusted_navigation("http://xn--truted-1wa.com:8000") is False


def test_cyrillic_homoglyph_in_domain(verifier):
    """http://tгusted.com (Cyrillic г) must be rejected."""
    assert verifier._is_trusted_navigation("http://t\u0433usted.com:8000") is False


def test_cyrillic_homoglyph_in_localhost(verifier):
    """http://lоcalhost:8000 (Cyrillic о) must be rejected."""
    assert verifier._is_trusted_navigation("http://l\u043Ecalhost:8000") is False


# ---------------------------------------------------------------------------
# 4. Hex / Octal / Decimal IPs (Non-canonical representations must be rejected)
# ---------------------------------------------------------------------------

def test_decimal_ip_rejected(verifier):
    """http://2130706433:8000 (decimal for 127.0.0.1) must not match literal allowlist."""
    assert verifier._is_trusted_navigation("http://2130706433:8000") is False


def test_octal_dotted_ip_rejected(verifier):
    """http://0177.0.0.1:8000 (octal dotted for 127.0.0.1) must be rejected."""
    assert verifier._is_trusted_navigation("http://0177.0.0.1:8000") is False


def test_hex_dotted_ip_rejected(verifier):
    """http://0x7f.0.0.1:8000 (hex dotted for 127.0.0.1) must be rejected."""
    assert verifier._is_trusted_navigation("http://0x7f.0.0.1:8000") is False


def test_hex_dword_ip_rejected(verifier):
    """http://0x7f000001:8000 (dword hex for 127.0.0.1) must be rejected."""
    assert verifier._is_trusted_navigation("http://0x7f000001:8000") is False


# ---------------------------------------------------------------------------
# 5. Trailing Dots (FQDN normalization)
# ---------------------------------------------------------------------------

def test_trailing_dot_on_trusted_allowed(verifier):
    """http://trusted.com.:8000/ should normalize to trusted.com:8000 and be accepted."""
    assert verifier._is_trusted_navigation("http://trusted.com.:8000/") is True


def test_trailing_dot_on_localhost_allowed(verifier):
    """http://localhost.:8000/ should normalize to localhost:8000 and be accepted."""
    assert verifier._is_trusted_navigation("http://localhost.:8000/") is True


def test_trailing_dot_on_attacker_rejected(verifier):
    """http://attacker.com.:8000/ must be rejected."""
    assert verifier._is_trusted_navigation("http://attacker.com.:8000/") is False


def test_trailing_dot_after_port_rejected(verifier):
    """http://trusted.com:8000. (trailing dot after port) is malformed and must be rejected."""
    assert verifier._is_trusted_navigation("http://trusted.com:8000.") is False


# ---------------------------------------------------------------------------
# 6. Port Mismatch (Port must match allowlist specification)
# ---------------------------------------------------------------------------

def test_port_mismatch_different_port_rejected(verifier):
    """http://127.0.0.1:8001 when allowlist specifies 8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8001/search") is False


def test_port_mismatch_standard_port_when_custom_required(verifier):
    """http://127.0.0.1:80 when allowlist specifies 8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:80/search") is False


def test_port_mismatch_high_port_rejected(verifier):
    """http://trusted.com:8080 when allowlist specifies 8000 must be rejected."""
    assert verifier._is_trusted_navigation("http://trusted.com:8080/") is False


# ---------------------------------------------------------------------------
# 7. Protocol-Relative '//host' (Must require explicit http/https scheme)
# ---------------------------------------------------------------------------

def test_protocol_relative_attacker_rejected(verifier):
    """//attacker.com must be rejected."""
    assert verifier._is_trusted_navigation("//attacker.com") is False


def test_protocol_relative_trusted_host_rejected(verifier):
    """//127.0.0.1:8000 (missing explicit scheme) must be rejected."""
    assert verifier._is_trusted_navigation("//127.0.0.1:8000") is False


def test_protocol_relative_with_path_rejected(verifier):
    """//localhost:8000/search must be rejected."""
    assert verifier._is_trusted_navigation("//localhost:8000/search") is False


# ---------------------------------------------------------------------------
# 8. javascript: and data: URIs (Dangerous pseudo-protocols must be rejected)
# ---------------------------------------------------------------------------

def test_javascript_uri_rejected(verifier):
    """javascript:alert(1) must be rejected."""
    assert verifier._is_trusted_navigation("javascript:alert(1)") is False


def test_javascript_void_rejected(verifier):
    """javascript:void(0) must be rejected."""
    assert verifier._is_trusted_navigation("javascript:void(0)") is False


def test_data_html_uri_rejected(verifier):
    """data:text/html,<script>alert(1)</script> must be rejected."""
    assert verifier._is_trusted_navigation("data:text/html,<script>alert(1)</script>") is False


def test_data_json_uri_rejected(verifier):
    """data:application/json,{\"steal\": 1} must be rejected."""
    assert verifier._is_trusted_navigation("data:application/json,{\"steal\": 1}") is False


def test_file_uri_rejected(verifier):
    """file:///etc/passwd must be rejected."""
    assert verifier._is_trusted_navigation("file:///etc/passwd") is False


# ---------------------------------------------------------------------------
# 9. Percent-Encoding (Normalized host decoding)
# ---------------------------------------------------------------------------

def test_percent_encoded_trusted_host_allowed(verifier):
    """http://%74%72%75%73%74%65%64.com:8000 decodes to trusted.com:8000 and is allowed."""
    assert verifier._is_trusted_navigation("http://%74%72%75%73%74%65%64.com:8000/") is True


def test_percent_encoded_evil_host_rejected(verifier):
    """http://%65%76%69%6c.com:8000 decodes to evil.com:8000 and must be rejected."""
    assert verifier._is_trusted_navigation("http://%65%76%69%6c.com:8000/") is False


# ---------------------------------------------------------------------------
# 10. Open-Redirect Parameters (Query params pointing to external untrusted targets)
# ---------------------------------------------------------------------------

def test_open_redirect_url_param_to_attacker_rejected(verifier):
    """http://127.0.0.1:8000/login?url=http://attacker.com must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/login?url=http://attacker.com") is False


def test_open_redirect_next_param_to_evil_rejected(verifier):
    """http://127.0.0.1:8000/auth?next=https://evil.com/leak must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/auth?next=https://evil.com/leak") is False


def test_open_redirect_target_protocol_relative_rejected(verifier):
    """http://127.0.0.1:8000/out?target=//attacker.com must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/out?target=//attacker.com") is False


def test_open_redirect_goto_javascript_rejected(verifier):
    """http://127.0.0.1:8000/nav?goto=javascript:alert(1) must be rejected."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/nav?goto=javascript:alert(1)") is False


def test_open_redirect_to_trusted_destination_allowed(verifier):
    """http://127.0.0.1:8000/login?next=http://127.0.0.1:8000/dashboard should be allowed."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/login?next=http://127.0.0.1:8000/dashboard") is True


def test_open_redirect_to_relative_path_allowed(verifier):
    """http://127.0.0.1:8000/login?next=/dashboard should be allowed."""
    assert verifier._is_trusted_navigation("http://127.0.0.1:8000/login?next=/dashboard") is True


# ---------------------------------------------------------------------------
# 11. Case Normalization (Upper / Mixed Case)
# ---------------------------------------------------------------------------

def test_uppercase_scheme_and_host_allowed(verifier):
    """HTTP://127.0.0.1:8000/SEARCH should normalize to lowercase and be accepted."""
    assert verifier._is_trusted_navigation("HTTP://127.0.0.1:8000/SEARCH") is True


def test_mixed_case_localhost_allowed(verifier):
    """hTtPs://LoCaLhOsT:8000/ should normalize and be accepted."""
    assert verifier._is_trusted_navigation("http://LoCaLhOsT:8000/") is True


def test_uppercase_attacker_rejected(verifier):
    """HTTP://ATTACKER.COM:8000/ must be rejected."""
    assert verifier._is_trusted_navigation("HTTP://ATTACKER.COM:8000/") is False


# ---------------------------------------------------------------------------
# 12. Valid Legitimate Allowlist Hits
# ---------------------------------------------------------------------------

def test_exact_trusted_domain_with_default_port(verifier):
    """http://trusted.com/page should match allowlist entry 'trusted.com'."""
    assert verifier._is_trusted_navigation("http://trusted.com/page") is True


def test_exact_trusted_subdomain_with_ssl(verifier):
    """https://api.trusted.com:443/v1 should match 'api.trusted.com:443'."""
    assert verifier._is_trusted_navigation("https://api.trusted.com:443/v1") is True
