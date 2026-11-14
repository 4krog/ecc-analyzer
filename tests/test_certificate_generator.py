import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from certificate_generator import generate_server_certificate
from ecc_analyzer.certificates import load_certificate


def make_intermediate(eku=None, name_constraints=None, scalar=None):
    key = ec.derive_private_key(scalar, ec.SECP384R1()) if scalar else ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "4KROG Intermediate CA")])
    now = datetime.now(timezone.utc)
    builder = (
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
    )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    return key, builder.sign(key, hashes.SHA384())


class CertificateGeneratorTests(unittest.TestCase):
    def test_certificate_loader_preserves_missing_file_error(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FileNotFoundError):
                load_certificate(Path(temp) / "missing.pem")

    def test_issued_certificate_is_signed_and_outputs_are_protected(self):
        ca_key, intermediate = make_intermediate(scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            paths = generate_server_certificate(
                intermediate=intermediate,
                private_scalar=4,
                subject_cn="banco.4krog.test",
                dns_names=["banco.4krog.test", "www.banco.4krog.test"],
                validity_days=7,
                output_dir=output,
            )
            issued = x509.load_pem_x509_certificate(paths["certificate"].read_bytes())
            ca_key.public_key().verify(
                issued.signature, issued.tbs_certificate_bytes,
                ec.ECDSA(issued.signature_hash_algorithm),
            )
            self.assertEqual(issued.issuer, intermediate.subject)
            self.assertEqual(
                issued.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName),
                ["banco.4krog.test", "www.banco.4krog.test"],
            )
            self.assertFalse(issued.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(stat.S_IMODE(paths["key"].stat().st_mode), 0o600)
            self.assertTrue(paths["fullchain"].read_bytes().endswith(intermediate.public_bytes(serialization.Encoding.PEM)))
            with self.assertRaises(FileExistsError):
                generate_server_certificate(
                    intermediate, 4, "banco.4krog.test",
                    ["banco.4krog.test"], 7, output,
                )

    def test_accepts_valid_dns_names_outside_test_namespace(self):
        _, intermediate = make_intermediate(scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            result = generate_server_certificate(
                intermediate, 4, "service.example.com",
                ["service.example.com", "api.example.org"], 7, temp,
            )
            issued = x509.load_pem_x509_certificate(result["certificate"].read_bytes())
            names = issued.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
            self.assertEqual(names, ["service.example.com", "api.example.org"])

    def test_dns_name_constraints_permitted_subtrees_are_enforced(self):
        constraints = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(".4krog.test")],
            excluded_subtrees=None,
        )
        _, intermediate = make_intermediate(scalar=4, name_constraints=constraints)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "permitted DNS NameConstraints"):
                generate_server_certificate(
                    intermediate, 4, "other.test", ["other.test"], 7, temp,
                )

    def test_dns_name_constraints_excluded_subtrees_are_enforced(self):
        constraints = x509.NameConstraints(
            permitted_subtrees=None,
            excluded_subtrees=[x509.DNSName(".4krog.test")],
        )
        _, intermediate = make_intermediate(scalar=4, name_constraints=constraints)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "excluded by"):
                generate_server_certificate(
                    intermediate, 4, "banco.4krog.test", ["banco.4krog.test"], 7, temp,
                )

    def test_ca_eku_must_permit_tls_server_authentication(self):
        _, intermediate = make_intermediate(eku=[ExtendedKeyUsageOID.CLIENT_AUTH], scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "EKU does not permit TLS server authentication"):
                generate_server_certificate(
                    intermediate, 4, "banco.4krog.test",
                    ["banco.4krog.test"], 7, temp,
                )

    def test_ca_eku_server_auth_and_any_eku_are_accepted(self):
        for index, eku in enumerate((
            [ExtendedKeyUsageOID.SERVER_AUTH],
            [ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE],
        )):
            _, intermediate = make_intermediate(eku=eku, scalar=4)
            with tempfile.TemporaryDirectory() as temp:
                result = generate_server_certificate(
                    intermediate, 4, "banco.4krog.test",
                    ["banco.4krog.test"], 7, Path(temp) / str(index),
                )
                self.assertTrue(result["certificate"].is_file())

    def test_ca_without_eku_remains_usable(self):
        _, intermediate = make_intermediate(scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            result = generate_server_certificate(
                intermediate, 4, "banco.4krog.test",
                ["banco.4krog.test"], 7, Path(temp) / "no-eku",
            )
            self.assertTrue(result["certificate"].is_file())

    def test_wrong_scalar_is_rejected(self):
        _, intermediate = make_intermediate(scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "NO MATCH"):
                generate_server_certificate(
                    intermediate, 1, "banco.4krog.test",
                    ["banco.4krog.test"], 7, temp,
                )

    def test_boolean_float_and_invalid_dns_inputs_are_rejected(self):
        _, intermediate = make_intermediate(scalar=4)
        with tempfile.TemporaryDirectory() as temp:
            for scalar in (True, 1.5):
                with self.subTest(scalar=scalar), self.assertRaisesRegex(ValueError, "private scalar"):
                    generate_server_certificate(
                        intermediate, scalar, "banco.4krog.test",
                        ["banco.4krog.test"], 7, Path(temp) / "scalar",
                    )
            for days in (True, 7.5):
                with self.subTest(days=days), self.assertRaisesRegex(ValueError, "Validity must be an integer"):
                    generate_server_certificate(
                        intermediate, 4, "banco.4krog.test",
                        ["banco.4krog.test"], days, Path(temp) / "days",
                    )
            for names in (None, "banco.4krog.test", [None], ["*.banco.4krog.test"]):
                with self.subTest(names=names), self.assertRaises(ValueError):
                    generate_server_certificate(
                        intermediate, 4, "banco.4krog.test", names, 7,
                        Path(temp) / "names",
                    )

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL CLI is required")
    def test_openssl_validates_trusted_tls_chain_and_rejects_wrong_hostname(self):
        root_key = ec.generate_private_key(ec.SECP384R1())
        intermediate_key = ec.generate_private_key(ec.SECP384R1())
        now = datetime.now(timezone.utc)
        root_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "4KROG Test Root CA")])
        intermediate_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "4KROG Test Intermediate CA")])
        root = (
            x509.CertificateBuilder()
            .subject_name(root_subject).issuer_name(root_subject)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before((now - timedelta(days=1)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=30)).replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=None, decipher_only=None,
            ), critical=True)
            .sign(root_key, hashes.SHA384())
        )
        intermediate = (
            x509.CertificateBuilder()
            .subject_name(intermediate_subject).issuer_name(root.subject)
            .public_key(intermediate_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before((now - timedelta(hours=12)).replace(tzinfo=None))
            .not_valid_after((now + timedelta(days=14)).replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=None, decipher_only=None,
            ), critical=True)
            .sign(root_key, hashes.SHA384())
        )

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root_path = directory / "root.pem"
            intermediate_path = directory / "intermediate.pem"
            root_path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
            intermediate_path.write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
            paths = generate_server_certificate(
                intermediate=intermediate,
                private_scalar=intermediate_key.private_numbers().private_value,
                subject_cn="service.example.test",
                dns_names=["service.example.test", "www.service.example.test"],
                validity_days=7,
                output_dir=directory / "output",
            )
            command = [
                "openssl", "verify", "-CAfile", str(root_path),
                "-untrusted", str(intermediate_path), "-purpose", "sslserver",
                "-verify_hostname", "service.example.test", str(paths["certificate"]),
            ]
            valid = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)
            self.assertIn(": OK", valid.stdout)

            wrong = command.copy()
            wrong[wrong.index("service.example.test")] = "wrong.example.test"
            invalid = subprocess.run(wrong, capture_output=True, text=True, check=False)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("hostname mismatch", (invalid.stdout + invalid.stderr).lower())


if __name__ == "__main__":
    unittest.main()
