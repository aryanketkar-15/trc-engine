"""tests/threat_agent/unit/test_pii_redaction.py
==============================================================================
TRC Engine -- Phase 1: Threat Agent  |  PII Redaction Unit Tests
------------------------------------------------------------------------------
Verifies:
    1. redact_pii() accurately masks emails, phones, SSNs, and IP addresses.
    2. Non-PII engineering terms (e.g. CWE-306, BLE 5.0, AS-1) are preserved.
    3. Planted PII inside free-text use_case and damage_scenario strings is masked.
    4. redact_structure() recursively sanitizes dict/list values while preserving keys.
"""

from __future__ import annotations

import unittest

from common.pii_redaction import (
    TOKEN_EMAIL,
    TOKEN_GOV_ID,
    TOKEN_IP,
    TOKEN_PHONE,
    redact_pii,
    redact_pii_with_count,
    redact_structure,
)


class TestPiiRedactionUnit(unittest.TestCase):
    """Direct unit tests for common/pii_redaction.py."""

    def test_email_redaction(self):
        text = "Contact the admin at security.lead@acme-corp.org for escalations."
        sanitized, count = redact_pii_with_count(text)
        assert count == 1
        assert "security.lead@acme-corp.org" not in sanitized
        assert TOKEN_EMAIL in sanitized

    def test_phone_redaction_punctuated(self):
        samples = [
            "Call +1-555-867-5309 immediately.",
            "Emergency dispatch: (555) 234-5678 on call.",
            "Contact desk 555-123-4567 for support.",
        ]
        for s in samples:
            sanitized = redact_pii(s)
            assert TOKEN_PHONE in sanitized
            assert "555" not in sanitized or TOKEN_PHONE in sanitized

    def test_phone_redaction_raw_digits(self):
        text = "Engineer mobile: +15551234567 assigned to lock firmware."
        sanitized = redact_pii(text)
        assert "15551234567" not in sanitized
        assert TOKEN_PHONE in sanitized

    def test_gov_id_ssn_redaction(self):
        text = "Technician badge SSN reference: 012-34-5678 found in device config."
        sanitized, count = redact_pii_with_count(text)
        assert count == 1
        assert "012-34-5678" not in sanitized
        assert TOKEN_GOV_ID in sanitized

    def test_ipv4_redaction(self):
        text = "Backend debug interface listening on 192.168.1.105 with admin access."
        sanitized, count = redact_pii_with_count(text)
        assert count == 1
        assert "192.168.1.105" not in sanitized
        assert TOKEN_IP in sanitized

    def test_engineering_terms_not_corrupted(self):
        """Standard protocol versions and identifiers must not be falsely masked."""
        terms = [
            "BLE 5.0 interface with GATT characteristics",
            "CWE-306 Missing Authentication for Critical Function",
            "CAPEC-94 Adversary in the Middle",
            "Asset AS-1 in untrusted zone",
            "Firmware build v1.2.3 running on ARM Cortex-M4",
        ]
        for t in terms:
            sanitized, count = redact_pii_with_count(t)
            assert count == 0
            assert sanitized == t

    def test_planted_pii_in_use_case_and_damage_scenario(self):
        """Assert planted email and phone in use_case and damage_scenario are masked."""
        use_case = (
            "Smart Door Lock system managed by alice.smith@hospital.org (+1-555-321-9876) "
            "allowing Bluetooth LE unlocking."
        )
        damage_scenario = (
            "Attacker impersonates tech with SSN 987-65-4321 to unlock ward doors, "
            "contacting command server at 10.0.1.50."
        )

        clean_uc = redact_pii(use_case)
        assert "alice.smith@hospital.org" not in clean_uc
        assert "+1-555-321-9876" not in clean_uc
        assert TOKEN_EMAIL in clean_uc
        assert TOKEN_PHONE in clean_uc

        clean_ds = redact_pii(damage_scenario)
        assert "987-65-4321" not in clean_ds
        assert "10.0.1.50" not in clean_ds
        assert TOKEN_GOV_ID in clean_ds
        assert TOKEN_IP in clean_ds

    def test_redact_structure_preserves_keys(self):
        """Dictionary keys must remain intact while string values are redacted."""
        config = {
            "admin_contact": "sysadmin@doorlock.io",
            "backup_phone": "555-888-9999",
            "port": 8080,
            "enabled": True,
            "nested": {
                "server_ip": "172.16.254.1",
            },
        }

        sanitized, count = redact_structure(config)
        assert count == 3
        # Keys must be untouched
        assert "admin_contact" in sanitized
        assert "backup_phone" in sanitized
        assert "port" in sanitized
        assert sanitized["port"] == 8080
        assert sanitized["enabled"] is True
        # Values must be redacted
        assert sanitized["admin_contact"] == TOKEN_EMAIL
        assert sanitized["backup_phone"] == TOKEN_PHONE
        assert sanitized["nested"]["server_ip"] == TOKEN_IP


if __name__ == "__main__":
    unittest.main()
