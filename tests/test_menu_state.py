import contextlib
import importlib.util
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


MODULE_PATH = Path(__file__).resolve().parents[1] / "ecc-analyzer.py"
SPEC = importlib.util.spec_from_file_location("ecc_analyzer", MODULE_PATH)
ecc_analyzer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ecc_analyzer)


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

        generate.assert_called_once_with(self.cert, self.scalar)
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


if __name__ == "__main__":
    unittest.main()
