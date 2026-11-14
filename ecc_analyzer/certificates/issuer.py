"""Issue TLS server certificates using a verified CA key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_VALIDITY_DAYS = 397


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


def _normalize_dns_name(value: str, *, allow_single_label: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("DNS names must be strings.")
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or "*" in name:
        raise ValueError(f"Invalid DNS name: {value!r}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid DNS name: {value!r}") from exc
    labels = ascii_name.split(".")
    if len(ascii_name) > 253 or (len(labels) < 2 and not allow_single_label) or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"Invalid DNS name: {value!r}")
    return ascii_name


def _normalize_dns_names(names: tuple[str, ...] | list[str]) -> list[str]:
    if not isinstance(names, (tuple, list)) or not names:
        raise ValueError("At least one SAN DNS name is required.")
    normalized: list[str] = []
    for raw_name in names:
        name = _normalize_dns_name(raw_name)
        if name not in normalized:
            normalized.append(name)
    return normalized


def _normalize_dns_constraint(value: str) -> tuple[bool, str]:
    if not isinstance(value, str):
        raise ValueError("The CA certificate contains an invalid DNS name constraint.")
    subdomains_only = value.startswith(".")
    base = value[1:] if subdomains_only else value
    if not base or base.startswith("."):
        raise ValueError("The CA certificate contains an invalid DNS name constraint.")
    return subdomains_only, _normalize_dns_name(base, allow_single_label=True)


def _matches_dns_constraint(name: str, constraint: tuple[bool, str]) -> bool:
    subdomains_only, base = constraint
    if subdomains_only:
        return name.endswith("." + base)
    return name == base or name.endswith("." + base)


def _enforce_name_constraints(intermediate: x509.Certificate, dns_names: list[str]) -> None:
    """Apply DNS NameConstraints from the issuing CA to every requested DNS name."""
    try:
        extension = intermediate.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return

    permitted = [
        _normalize_dns_constraint(item.value)
        for item in (extension.permitted_subtrees or ())
        if isinstance(item, x509.DNSName)
    ]
    excluded = [
        _normalize_dns_constraint(item.value)
        for item in (extension.excluded_subtrees or ())
        if isinstance(item, x509.DNSName)
    ]

    for name in dns_names:
        if any(_matches_dns_constraint(name, item) for item in excluded):
            raise ValueError(f"{name} is excluded by the intermediate CA NameConstraints.")
        if permitted and not any(_matches_dns_constraint(name, item) for item in permitted):
            raise ValueError(f"{name} is outside the intermediate CA permitted DNS NameConstraints.")


def generate_server_certificate(
    intermediate: x509.Certificate,
    private_scalar: int,
    subject_cn: str,
    dns_names: tuple[str, ...] | list[str],
    validity_days: int,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Verify a CA scalar and issue a TLS server certificate for valid DNS names.

    The CA must be currently valid and authorized for certificate signing.
    The scalar must match its EC public key. Existing output files are never
    overwritten. DNS NameConstraints and CA EKU restrictions are enforced.

    This function verifies the generated certificate signature; it does not
    build or validate the complete chain to a trusted root, hostname trust,
    or revocation status.
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

    try:
        ca_eku = intermediate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        ca_eku = None
    if ca_eku is not None and not (
        ExtendedKeyUsageOID.SERVER_AUTH in ca_eku
        or ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in ca_eku
    ):
        raise ValueError("The intermediate CA EKU does not permit TLS server authentication.")

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

    normalized_names = _normalize_dns_names(dns_names)
    normalized_cn = _normalize_dns_name(subject_cn)
    if normalized_cn not in normalized_names:
        raise ValueError("Subject CN must be one of the SAN DNS names.")
    _enforce_name_constraints(intermediate, normalized_names)

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
        key_fd = os.open(paths["key"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created.append(paths["key"])
        with os.fdopen(key_fd, "wb") as output:
            output.write(payloads["key"])
        for label in ("csr", "certificate", "fullchain"):
            path = paths[label]
            with path.open("xb") as output:
                created.append(path)
                output.write(payloads[label])
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return paths
