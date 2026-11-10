"""Issue lab-scoped TLS certificates using a verified intermediate CA key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .profile import MAX_VALIDITY_DAYS, validate_dns_names


def _certificate_time(cert: x509.Certificate, utc_name: str, legacy_name: str) -> datetime:
    value = getattr(cert, utc_name, None)
    if value is None:
        value = getattr(cert, legacy_name).replace(tzinfo=timezone.utc)
    return value


def _signature_hash(public_key: ec.EllipticCurvePublicKey) -> hashes.HashAlgorithm:
    if public_key.key_size >= 521:
        return hashes.SHA512()
    if public_key.key_size >= 384:
        return hashes.SHA384()
    return hashes.SHA256()


def generate_server_certificate(
    intermediate: x509.Certificate,
    private_scalar: int,
    subject_cn: str,
    dns_names: tuple[str, ...] | list[str],
    validity_days: int,
    output_dir: str | Path,
    allowed_dns_suffixes: tuple[str, ...] | list[str],
) -> dict[str, Path]:
    """Verify the CA scalar and issue a profile-scoped TLS server certificate.

    The intermediate must be a currently valid EC CA with certificate-signing
    key usage, and private_scalar must match its public key. Output files are
    created exclusively and existing files are never overwritten.

    Raises:
        ValueError: Invalid CA, scalar, validity, DNS scope, or certificate data.
        FileExistsError: Any target output file already exists.
        OSError: The output directory or files cannot be created/written.
        TypeError: output_dir is not path-like or an underlying cryptography
            operation receives an unsupported value.
    """
    if not isinstance(intermediate, x509.Certificate):
        raise ValueError("The intermediate must be an X.509 certificate.")
    if not isinstance(subject_cn, str):
        raise ValueError("Subject CN must be a DNS name string.")
    if not isinstance(dns_names, (tuple, list)):
        raise ValueError("SAN DNS names must be supplied as a list or tuple.")
    if type(private_scalar) is not int or private_scalar <= 0:
        raise ValueError("The private scalar must be a positive integer.")
    if type(validity_days) is not int or not 1 <= validity_days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"Validity must be an integer between 1 and {MAX_VALIDITY_DAYS} days.")

    ca_public = intermediate.public_key()
    if not isinstance(ca_public, ec.EllipticCurvePublicKey):
        raise ValueError("The supplied certificate does not contain an EC public key.")

    try:
        constraints = intermediate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = intermediate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError(f"Required CA extension missing: {exc}") from exc
    if not constraints.ca or not usage.key_cert_sign:
        raise ValueError("The supplied certificate is not authorized to sign certificates.")

    now = datetime.now(timezone.utc)
    ca_not_before = _certificate_time(intermediate, "not_valid_before_utc", "not_valid_before")
    ca_not_after = _certificate_time(intermediate, "not_valid_after_utc", "not_valid_after")
    if not ca_not_before <= now <= ca_not_after:
        raise ValueError("The intermediate CA certificate is not currently valid.")

    try:
        ca_private = ec.derive_private_key(private_scalar, ca_public.curve)
    except (ValueError, OverflowError) as exc:
        raise ValueError("The supplied scalar is outside the valid range for this curve.") from exc
    if ca_private.public_key().public_numbers() != ca_public.public_numbers():
        raise ValueError("NO MATCH: the supplied scalar does not correspond to this CA certificate.")

    normalized_names = validate_dns_names(dns_names, allowed_dns_suffixes)
    normalized_cn = validate_dns_names([subject_cn], allowed_dns_suffixes)[0]
    if normalized_cn not in normalized_names:
        raise ValueError("Subject CN must be one of the SAN DNS names.")

    not_before = max(now - timedelta(minutes=5), ca_not_before)
    not_after = min(now + timedelta(days=validity_days), ca_not_after)
    if not_after <= not_before:
        raise ValueError("The requested certificate validity exceeds the CA certificate validity.")

    digest = _signature_hash(ca_public)
    server_key = ec.generate_private_key(ca_public.curve)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, normalized_cn)])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name) for name in normalized_names]), critical=False)
        .sign(server_key, digest)
    )
    if not csr.is_signature_valid:
        raise ValueError("Generated CSR signature validation failed.")

    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(intermediate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value, critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=None, decipher_only=None,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_public), critical=False)
        .sign(ca_private, digest)
    )

    # Verify the issued certificate's signature before writing any private material.
    ca_public.verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        ec.ECDSA(certificate.signature_hash_algorithm),
    )

    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "key": output_dir / "server.key",
        "csr": output_dir / "server.csr",
        "certificate": output_dir / "server.crt",
        "fullchain": output_dir / "fullchain.pem",
    }
    conflicts = [str(path) for path in paths.values() if path.exists()]
    if conflicts:
        raise FileExistsError("Refusing to overwrite existing output: " + ", ".join(conflicts))

    payloads = {
        "key": server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "csr": csr.public_bytes(serialization.Encoding.PEM),
        "certificate": certificate.public_bytes(serialization.Encoding.PEM),
        "fullchain": (
            certificate.public_bytes(serialization.Encoding.PEM)
            + intermediate.public_bytes(serialization.Encoding.PEM)
        ),
    }
    created: list[Path] = []
    try:
        for label, path in paths.items():
            with path.open("xb") as output:
                created.append(path)
                output.write(payloads[label])
        paths["key"].chmod(0o600)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return paths
