import unittest

from attacker_sim import query_path
from honeypot import AttackTracker, detect_attack_patterns


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


if __name__ == "__main__":
    unittest.main()
