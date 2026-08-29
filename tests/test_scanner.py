import os
import tempfile
import unittest

from leakhound.scanner import Config, scan_paths


class TestScanner(unittest.TestCase):
    def _write(self, root, rel, content):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_finds_secrets_in_file(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "config.env",
                        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
                        "-----BEGIN RSA PRIVATE KEY-----\n")
            findings = scan_paths(Config(paths=[root]))
            ids = {f.rule_id for f in findings}
            self.assertIn("github_pat", ids)
            self.assertIn("private_key", ids)

    def test_allow_marker_suppresses(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "config.env",
                        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz  # leakhound:allow\n")
            findings = scan_paths(Config(paths=[root]))
            self.assertEqual(findings, [])

    def test_ignore_file_excludes_path(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "secrets/leak.env",
                        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
            self._write(root, ".leakhoundignore", "secrets/\n")
            findings = scan_paths(Config(paths=[root]))
            self.assertEqual(findings, [])

    def test_binary_is_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "blob.bin")
            with open(path, "wb") as fh:
                fh.write(b"\x00\x01ghp_0123456789abcdefghijklmnopqrstuvwxyz")
            findings = scan_paths(Config(paths=[root]))
            self.assertEqual(findings, [])

    def test_masking_hides_middle(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "config.env",
                        "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
            findings = scan_paths(Config(paths=[root]))
            masked = findings[0].masked()
            self.assertTrue(masked.startswith("ghp_"))
            self.assertIn("*", masked)
            self.assertNotEqual("ghp_0123456789abcdefghijklmnopqrstuvwxyz", masked)


if __name__ == "__main__":
    unittest.main()
