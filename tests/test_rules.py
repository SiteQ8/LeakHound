import unittest

from leakhound.scanner import Config, scan_line


def rule_ids(line, **kwargs):
    cfg = Config(**kwargs)
    return {rule.id for rule, _secret, _col in scan_line(line, cfg)}


class TestRules(unittest.TestCase):
    def test_github_pat(self):
        line = "token = ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        self.assertIn("github_pat", rule_ids(line, use_entropy=False))

    def test_aws_access_key(self):
        self.assertIn("aws_access_key_id", rule_ids("key: AKIAIOSFODNN7EXAMPLE", use_entropy=False))

    def test_private_key(self):
        self.assertIn("private_key", rule_ids("-----BEGIN RSA PRIVATE KEY-----", use_entropy=False))

    def test_stripe(self):
        # Built at runtime so the fixture is not stored as one contiguous token.
        sample = "s=sk_" + "live_4eC39HqLyjWDarjtT1zdp7dc"
        self.assertIn("stripe_secret_key", rule_ids(sample, use_entropy=False))

    def test_basic_auth_url(self):
        line = "DATABASE_URL=postgres://admin:S3cr3tP4ssw0rd@db.internal:5432/app"
        self.assertIn("basic_auth_url", rule_ids(line, use_entropy=False))

    def test_placeholder_not_flagged(self):
        # A clearly fake assignment should not trip the heuristic rules.
        ids = rule_ids('password = "changeme"', use_entropy=True)
        self.assertNotIn("generic_secret_assignment", ids)

    def test_plain_prose_is_clean(self):
        line = "The quick brown fox jumps over the lazy dog."
        self.assertEqual(rule_ids(line, use_entropy=True), set())


if __name__ == "__main__":
    unittest.main()
