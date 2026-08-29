import unittest

from leakhound.entropy import shannon_entropy


class TestEntropy(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_is_zero(self):
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_random_is_high(self):
        self.assertGreater(shannon_entropy("wJalrXUtnFEMI7K3MDENGbPxRf1CYz9q"), 4.0)

    def test_more_variety_more_entropy(self):
        low = shannon_entropy("aaaabbbb")
        high = shannon_entropy("abcdefgh")
        self.assertGreater(high, low)


if __name__ == "__main__":
    unittest.main()
