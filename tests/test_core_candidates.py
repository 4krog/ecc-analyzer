import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from ecc_analyzer.core import (
    find_matching_candidates,
    parse_candidate,
    parse_range,
    read_candidates,
    test_candidate,
)


class CandidateCoreTests(unittest.TestCase):
    def setUp(self):
        self.scalar = 123456789
        self.private_key = ec.derive_private_key(self.scalar, ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def test_parse_decimal_and_hex_candidates(self):
        self.assertEqual(parse_candidate("123456789"), self.scalar)
        self.assertEqual(parse_candidate("0x75bcd15"), self.scalar)
        self.assertEqual(parse_candidate("  123_456_789  "), self.scalar)

    def test_parse_candidate_rejects_non_positive_or_invalid_values(self):
        for value in ("", "0", "-1", "not-a-number", 123):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_candidate(value)

    def test_candidate_match_and_non_match(self):
        self.assertTrue(test_candidate(self.public_key, self.scalar))
        self.assertFalse(test_candidate(self.public_key, self.scalar + 1))
        self.assertFalse(test_candidate(self.public_key, 0))
        self.assertFalse(test_candidate(self.public_key, True))
        self.assertFalse(test_candidate(self.public_key, 1.5))
        with self.assertRaisesRegex(ValueError, "public_key must be"):
            test_candidate(object(), self.scalar)

    def test_find_matching_candidates_rejects_invalid_public_key(self):
        with self.assertRaisesRegex(ValueError, "public_key must be"):
            find_matching_candidates(object(), [self.scalar])

    def test_find_matching_candidates_deduplicates_values(self):
        matches = find_matching_candidates(
            self.public_key,
            [self.scalar, self.scalar + 1, self.scalar, 0, True, 1.5],
        )
        self.assertEqual(matches, (self.scalar,))

    def test_parse_inclusive_range_and_enforce_limit(self):
        self.assertEqual(list(parse_range("3:5")), [3, 4, 5])
        with self.assertRaises(ValueError):
            parse_range("1:11", maximum=10)
        with self.assertRaises(ValueError):
            parse_range("5:3")
        for maximum in (True, 0, -1, 2.5):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                parse_range("1:2", maximum=maximum)

    def test_read_candidates_supports_comments_and_hex(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidates.txt"
            path.write_text("# test values\n123456789\n0x75bcd16 # another candidate\n", encoding="utf-8")
            self.assertEqual(read_candidates(path), [self.scalar, self.scalar + 1])


if __name__ == "__main__":
    unittest.main()
