import unittest

from attacker_sim import query_path
from honeypot import AttackTracker, detect_attack_patterns
from threat_scoring import build_ip_risk_profiles, classify_risk, score_ip_entries


class AttackDetectionTests(unittest.TestCase):
    def test_normal_request_is_not_an_attack(self):
        self.assertEqual(detect_attack_patterns("/api/customers?id=1"), [])

    def test_url_encoded_sql_injection_is_detected(self):
        path = query_path("/api/customers", id="1 UNION SELECT * FROM users--")
        self.assertIn("sql_injection", detect_attack_patterns(path))

    def test_string_escape_sql_injection_is_detected(self):
        path = query_path("/api/customers", name="' OR ''='")
        self.assertIn("sql_injection", detect_attack_patterns(path))

    def test_url_encoded_xss_is_detected(self):
        path = query_path("/search", q='<script>alert("xss")</script>')
        self.assertIn("xss", detect_attack_patterns(path))

    def test_url_encoded_path_traversal_is_detected(self):
        self.assertIn(
            "path_traversal",
            detect_attack_patterns("/%2e%2e/%2e%2e/etc/passwd"),
        )

    def test_command_injection_in_body_is_detected(self):
        self.assertIn("command_injection", detect_attack_patterns("/run", "command=; cat /etc/passwd"))


class BruteForceDetectionTests(unittest.TestCase):
    def test_bruteforce_requires_repeated_attempts(self):
        tracker = AttackTracker()

        self.assertFalse(tracker.record_login_attempt("192.0.2.10", now=1))
        self.assertFalse(tracker.record_login_attempt("192.0.2.10", now=2))
        self.assertTrue(tracker.record_login_attempt("192.0.2.10", now=3))

    def test_old_login_attempts_expire(self):
        tracker = AttackTracker()

        tracker.record_login_attempt("192.0.2.10", now=1)
        tracker.record_login_attempt("192.0.2.10", now=2)

        self.assertFalse(tracker.record_login_attempt("192.0.2.10", now=40))


class ThreatScoringTests(unittest.TestCase):
    def test_clean_ip_is_info_level(self):
        profile = score_ip_entries([
            {"ip": "192.0.2.10", "attack_types": []},
            {"ip": "192.0.2.10", "attack_types": []},
        ])

        self.assertEqual(profile["score"], 0)
        self.assertEqual(profile["level"], "INFO")

    def test_dangerous_attacks_raise_risk_level(self):
        profile = score_ip_entries([
            {"ip": "192.0.2.10", "attack_types": ["sql_injection"]},
            {"ip": "192.0.2.10", "attack_types": ["login_bruteforce"]},
            {"ip": "192.0.2.10", "attack_types": ["command_injection"]},
        ])

        self.assertEqual(profile["score"], 14)
        self.assertEqual(profile["level"], "HIGH")

    def test_profiles_are_sorted_by_score(self):
        profiles = build_ip_risk_profiles([
            {"ip": "192.0.2.10", "attack_types": ["xss"]},
            {"ip": "198.51.100.5", "attack_types": ["command_injection"]},
            {"ip": "198.51.100.5", "attack_types": ["login_bruteforce"]},
        ])

        self.assertEqual(profiles[0]["ip"], "198.51.100.5")
        self.assertEqual(profiles[0]["level"], "MEDIUM")

    def test_risk_level_thresholds(self):
        self.assertEqual(classify_risk(0), "INFO")
        self.assertEqual(classify_risk(1), "LOW")
        self.assertEqual(classify_risk(5), "MEDIUM")
        self.assertEqual(classify_risk(12), "HIGH")
        self.assertEqual(classify_risk(20), "CRITICAL")


if __name__ == "__main__":
    unittest.main()
