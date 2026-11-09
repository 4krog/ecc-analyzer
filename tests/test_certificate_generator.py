import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from certificate_generator import generate_server_certificate, validate_dns_names


def make_intermediate():
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "4KROG Intermediate CA")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
        .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=None, decipher_only=None,
        ), critical=True)
        .sign(key, hashes.SHA384())
    )
    return key, cert


class CertificateGeneratorTests(unittest.TestCase):
    def test_dns_scope_rejects_outside_domain(self):
        with self.assertRaises(ValueError):
            validate_dns_names(["attacker.example"], (".4krog.test",))

    def test_dns_scope_accepts_lab_names(self):
        self.assertEqual(
            validate_dns_names(["BAnco.4krog.test", "api.4krog.test"], (".4krog.test",)),
            ["banco.4krog.test", "api.4krog.test"],
        )

    def test_issued_certificate_is_signed_and_outputs_are_protected(self):
        ca_key, intermediate = make_intermediate()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            paths = generate_server_certificate(
                intermediate=intermediate,
                private_scalar=ca_key.private_numbers().private_value,
                subject_cn="banco.4krog.test",
                dns_names=["banco.4krog.test", "www.banco.4krog.test"],
                validity_days=7,
                output_dir=output,
                allowed_dns_suffixes=(".4krog.test",),
            )
            issued = x509.load_pem_x509_certificate(paths["certificate"].read_bytes())
            ca_key.public_key().verify(
                issued.signature, issued.tbs_certificate_bytes,
                ec.ECDSA(issued.signature_hash_algorithm),
            )
            self.assertEqual(issued.issuer, intermediate.subject)
            self.assertEqual(paths["key"].stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                generate_server_certificate(
                    intermediate, ca_key.private_numbers().private_value,
                    "banco.4krog.test", ["banco.4krog.test"], 7,
                    output, (".4krog.test",),
                )

    def test_wrong_scalar_is_rejected(self):
        _, intermediate = make_intermediate()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "NO MATCH"):
                generate_server_certificate(
                    intermediate, 1, "banco.4krog.test",
                    ["banco.4krog.test"], 7, Path(temp) / "out",
                    (".4krog.test",),
                )


if __name__ == "__main__":
    unittest.main()
