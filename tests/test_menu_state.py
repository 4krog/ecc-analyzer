import contextlib
import io
import tempfile
import unittest
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ecc_analyzer import cli as ecc_analyzer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

def make_intermediate():
    scalar = 123456789
    key = ec.derive_private_key(scalar, ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "4KROG Test Intermediate CA")])
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
        .sign(key, hashes.SHA384())
    )
    return scalar, cert


class MainMenuStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scalar, self.cert = make_intermediate()
        self.cert_path = self.root / "intermediate.pem"
        self.cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))

    def run_menu(self, inputs):
        output = io.StringIO()
        with patch("builtins.input", side_effect=inputs), contextlib.redirect_stdout(output):
            ecc_analyzer.main_menu()
        return output.getvalue()

    def test_enter_keeps_certificate_and_verified_scalar(self):
        inputs = [
            "1", str(self.cert_path), "",  # load certificate
            "2", str(self.scalar), "",     # verify matching scalar
            "1", "", "",                   # Enter keeps current certificate
            "6", "",                       # generation is now unlocked
            "0",
        ]
        with patch.object(ecc_analyzer, "generate_certificate_interactive") as generate:
            output = self.run_menu(inputs)

        generate.assert_called_once_with(self.cert, self.scalar, None)
        self.assertIn("VERIFIED CANDIDATE: AVAILABLE FOR THIS CERTIFICATE", output)

    def test_failed_replacement_keeps_certificate_but_invalidates_scalar(self):
        invalid_path = self.root / "not-a-certificate.pem"
        invalid_path.write_text("not an X.509 certificate", encoding="utf-8")
        inputs = [
            "1", str(self.cert_path), "",   # load valid certificate
            "2", str(self.scalar), "",      # verify matching scalar
            "1", str(invalid_path), "",     # failed replacement; pause after error
            "6", "",                        # must be locked after replacement attempt
            "0",
        ]
        with patch.object(ecc_analyzer, "generate_certificate_interactive") as generate:
            output = self.run_menu(inputs)

        generate.assert_not_called()
        self.assertIn(f"LOADED: {self.cert_path}", output)
        self.assertIn("Could not parse an X.509 certificate", output)
        self.assertIn("verify a matching private-key candidate first", output)
        self.assertEqual(output.count("CERTIFICATE: NOT LOADED"), 1)


    def test_menu_generates_real_proof_of_impact_certificate(self):
        output_dir = self.root / "proof-of-impact"
        profile = SimpleNamespace(
            name="El ascensor chino",
            subject_cn="banco.4krog.test",
            dns_names=(
                "banco.4krog.test",
                "www.banco.4krog.test",
                "api.banco.4krog.test",
            ),
            validity_days=7,
            allowed_dns_suffixes=(".4krog.test",),
        )
        inputs = [
            "1", str(self.cert_path), "",  # load intermediate CA
            "2", str(self.scalar), "",     # verify matching CA scalar
            "6", "", "", "", str(output_dir), "",  # generate with profile defaults
            "0",
        ]
        with patch.object(ecc_analyzer, "load_profile", return_value=profile):
            output = self.run_menu(inputs)

        certificate_path = output_dir / "server.crt"
        key_path = output_dir / "server.key"
        csr_path = output_dir / "server.csr"
        fullchain_path = output_dir / "fullchain.pem"
        for path in (certificate_path, key_path, csr_path, fullchain_path):
            self.assertTrue(path.is_file(), f"Expected generated file: {path}")

        issued = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        self.cert.public_key().verify(
            issued.signature,
            issued.tbs_certificate_bytes,
            ec.ECDSA(issued.signature_hash_algorithm),
        )
        self.assertEqual(issued.issuer, self.cert.subject)
        self.assertEqual(
            issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),
            list(profile.dns_names),
        )
        self.assertFalse(issued.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)

        # The generated server key must match the public key embedded in the leaf.
        server_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        self.assertEqual(
            server_key.public_key().public_numbers(),
            issued.public_key().public_numbers(),
        )

        # The CSR must be valid and request the same public key and DNS names.
        csr = x509.load_pem_x509_csr(csr_path.read_bytes())
        self.assertTrue(csr.is_signature_valid)
        self.assertEqual(csr.public_key().public_numbers(), issued.public_key().public_numbers())
        self.assertEqual(
            csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),
            list(profile.dns_names),
        )

        # Check TLS server usage and the leaf's validity window.
        eku = issued.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, eku)
        usage = issued.extensions.get_extension_for_class(x509.KeyUsage).value
        self.assertTrue(usage.digital_signature)
        self.assertTrue(usage.key_encipherment is False)
        self.assertFalse(usage.key_cert_sign)
        self.assertLessEqual(issued.not_valid_after_utc, self.cert.not_valid_after_utc)
        self.assertLessEqual(
            issued.not_valid_after_utc - issued.not_valid_before_utc,
            timedelta(days=profile.validity_days, minutes=5),
        )

        # fullchain.pem must contain leaf first, followed by the supplied intermediate.
        chain = x509.load_pem_x509_certificates(fullchain_path.read_bytes())
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0].fingerprint(hashes.SHA256()), issued.fingerprint(hashes.SHA256()))
        self.assertEqual(chain[1].fingerprint(hashes.SHA256()), self.cert.fingerprint(hashes.SHA256()))

        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
        self.assertIn("CERTIFICATE CREATED AND SIGNATURE VERIFIED", output)



if __name__ == "__main__":
    unittest.main()
