"""Regression tests for unrestricted default certificate-profile DNS scope."""

import unittest

from ecc_analyzer.certificates import load_profile, validate_dns_names


class UnrestrictedDefaultProfileTests(unittest.TestCase):
    def test_bundled_default_profile_has_no_dns_suffix_restriction(self):
        profile = load_profile()
        self.assertEqual(profile.allowed_dns_suffixes, ())

    def test_empty_suffix_list_accepts_arbitrary_valid_dns_names(self):
        names = validate_dns_names(
            ["banco.4krog.test", "example.org", "subdomain.example.com"],
            [],
        )
        self.assertEqual(
            names,
            ["banco.4krog.test", "example.org", "subdomain.example.com"],
        )

    def test_empty_suffix_list_still_rejects_invalid_dns_names(self):
        with self.assertRaises(ValueError):
            validate_dns_names(["not a valid hostname"], [])


if __name__ == "__main__":
    unittest.main()
