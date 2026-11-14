import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ecc_analyzer.certificates.issuer import generate_server_certificate


def make_intermediate(scalar=4, name_constraints=None):
    private_key = ec.derive_private_key(scalar, ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")]))
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    return builder.sign(private_key, hashes.SHA384())


class CertificateIssuanceTests(unittest.TestCase):
    def test_issues_leaf_with_path_length_zero_ca(self):
        ca = make_intermediate()
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = generate_server_certificate(
                intermediate=ca,
                private_scalar=4,
                subject_cn="banco.4krog.test",
                dns_names=["banco.4krog.test", "www.banco.4krog.test"],
                validity_days=7,
                output_dir=temp_dir,
            )
            leaf = x509.load_pem_x509_certificate(paths["certificate"].read_bytes())
            ca.public_key().verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(leaf.signature_hash_algorithm),
            )
            self.assertFalse(leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(
                stat.S_IMODE(os.stat(paths["key"]).st_mode),
                0o600,
            )
            self.assertTrue(paths["fullchain"].read_bytes().endswith(ca.public_bytes(serialization.Encoding.PEM)))

    def test_accepts_valid_dns_names_outside_test_namespace(self):
        ca = make_intermediate()
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = generate_server_certificate(
                ca, 4, "service.example.com",
                ["service.example.com", "api.example.org"], 7, temp_dir
            )
            self.assertTrue(paths["certificate"].is_file())
            leaf = x509.load_pem_x509_certificate(paths["certificate"].read_bytes())
            names = leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            self.assertEqual(names, ["service.example.com", "api.example.org"])

    def test_enforces_ca_permitted_dns_name_constraints(self):
        constraints = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(".4krog.test")],
            excluded_subtrees=None,
        )
        ca = make_intermediate(name_constraints=constraints)
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "permitted DNS NameConstraints"):
                generate_server_certificate(
                    ca, 4, "other.test", ["other.test"], 7, temp_dir
                )

    def test_enforces_ca_excluded_dns_name_constraints(self):
        constraints = x509.NameConstraints(
            permitted_subtrees=None,
            excluded_subtrees=[x509.DNSName(".4krog.test")],
        )
        ca = make_intermediate(name_constraints=constraints)
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "excluded by"):
                generate_server_certificate(
                    ca, 4, "banco.4krog.test", ["banco.4krog.test"], 7, temp_dir
                )


if __name__ == "__main__":
    unittest.main()
