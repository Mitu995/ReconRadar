"""
test_reconradar.py
-------------------
Unit tests for Recon Radar's core logic — pattern matching, redaction,
normalization, and dedup behavior. Run with:

    pip install pytest
    pytest test_reconradar.py -v

These tests exercise pure functions only (no network calls), so they
run instantly and don't touch any real target.
"""

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import reconradar as rr


# ─────────────────────────────────────────────────────────────────────────
# JS secret pattern matching
# ─────────────────────────────────────────────────────────────────────────

class TestSecretPatterns:
    def test_aws_key_pattern_matches_valid_format(self):
        sample = "const key = 'AKIAIOSFODNN7EXAMPLE';"
        assert re.search(rr.JS_SECRET_PATTERNS["AWS Access Key"], sample)

    def test_aws_key_pattern_rejects_wrong_length(self):
        sample = "const key = 'AKIASHORT';"
        assert not re.search(rr.JS_SECRET_PATTERNS["AWS Access Key"], sample)

    def test_google_api_key_pattern_matches(self):
        sample = "apiKey: 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'"
        assert re.search(rr.JS_SECRET_PATTERNS["Google API Key"], sample)

    def test_slack_token_pattern_matches(self):
        sample = "token=xoxb-1234567890-abcdefghijklmnop"
        assert re.search(rr.JS_SECRET_PATTERNS["Slack Token"], sample)

    def test_stripe_key_pattern_matches_live_and_test(self):
        assert re.search(rr.JS_SECRET_PATTERNS["Stripe Key"], "sk_live_" + "a" * 24)
        assert re.search(rr.JS_SECRET_PATTERNS["Stripe Key"], "pk_test_" + "b" * 24)

    def test_jwt_pattern_matches_three_part_token(self):
        sample = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert re.search(rr.JS_SECRET_PATTERNS["JWT Token"], sample)

    def test_private_key_header_matches(self):
        sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        assert re.search(rr.JS_SECRET_PATTERNS["Private Key Header"], sample)

    def test_generic_secret_assignment_matches(self):
        sample = 'const password = "SuperSecret123!";'
        assert re.search(rr.JS_SECRET_PATTERNS["Generic Secret Assignment"], sample)

    def test_no_false_positive_on_plain_text(self):
        sample = "This is just a normal sentence about cybersecurity research."
        for label, pattern in rr.JS_SECRET_PATTERNS.items():
            assert not re.search(pattern, sample), f"Unexpected match for {label}"


# ─────────────────────────────────────────────────────────────────────────
# Redaction
# ─────────────────────────────────────────────────────────────────────────

class TestRedaction:
    def test_redact_hides_middle_of_long_secret(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        redacted = rr._redact(secret)
        assert secret not in redacted
        assert "..." in redacted
        assert redacted.startswith(secret[:6])
        assert redacted.endswith(secret[-4:])

    def test_redact_short_string_still_partially_hidden(self):
        secret = "shortkey"
        redacted = rr._redact(secret)
        assert secret != redacted
        assert "..." in redacted

    def test_redact_never_returns_full_original(self):
        for secret in ["AKIAIOSFODNN7EXAMPLE", "sk_live_" + "x" * 24, "12345678901234567890"]:
            assert rr._redact(secret) != secret


# ─────────────────────────────────────────────────────────────────────────
# Target normalization
# ─────────────────────────────────────────────────────────────────────────

class TestNormalizeTarget:
    def test_adds_https_when_missing_scheme(self):
        url, host = rr.normalize_target("example.com")
        assert url == "https://example.com"
        assert host == "example.com"

    def test_preserves_existing_https_scheme(self):
        url, host = rr.normalize_target("https://example.com")
        assert url == "https://example.com"
        assert host == "example.com"

    def test_preserves_existing_http_scheme(self):
        url, host = rr.normalize_target("http://example.com")
        assert url == "http://example.com"

    def test_extracts_hostname_correctly(self):
        _, host = rr.normalize_target("https://sub.example.com/path")
        assert host == "sub.example.com"


# ─────────────────────────────────────────────────────────────────────────
# Findings dedup (via the `found()` logging function)
# ─────────────────────────────────────────────────────────────────────────

class TestFindingsDedup:
    def setup_method(self):
        # reset global state between tests since found() uses module-level sets
        rr._SEEN_FINDINGS.clear()
        rr.LOG_LINES.clear()
        rr.JSON_FINDINGS["sections"] = {}

    def test_duplicate_finding_only_logged_once(self):
        rr.section("Test Section")
        rr.found("Duplicate finding message")
        rr.found("Duplicate finding message")
        printed_findings = [line for line in rr.LOG_LINES if "Duplicate finding message" in line]
        assert len(printed_findings) == 1

    def test_different_findings_both_logged(self):
        rr.section("Test Section")
        rr.found("First finding")
        rr.found("Second finding")
        assert any("First finding" in line for line in rr.LOG_LINES)
        assert any("Second finding" in line for line in rr.LOG_LINES)

    def test_finding_recorded_under_current_section_in_json(self):
        rr.section("My Section")
        rr.found("Something detected")
        assert "My Section" in rr.JSON_FINDINGS["sections"]
        messages = [f["message"] for f in rr.JSON_FINDINGS["sections"]["My Section"]]
        assert any("Something detected" in m for m in messages)


# ─────────────────────────────────────────────────────────────────────────
# Security headers config sanity checks
# ─────────────────────────────────────────────────────────────────────────

class TestSecurityHeadersConfig:
    def test_all_headers_have_severity_and_description(self):
        for header, (severity, desc) in rr.SECURITY_HEADERS.items():
            assert severity in ("High", "Medium", "Low")
            assert len(desc) > 0

    def test_sensitive_paths_list_not_empty(self):
        assert len(rr.SENSITIVE_PATHS) > 0

    def test_sensitive_paths_are_relative_not_absolute_urls(self):
        for path in rr.SENSITIVE_PATHS:
            assert not path.startswith("http"), f"{path} should be a relative path"


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
