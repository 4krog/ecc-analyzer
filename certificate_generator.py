"""Generate a lab-scoped TLS certificate after an EC private scalar is verified."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PROFILE_PATH = Path(__file__).resolve().parent / "profiles" / "el-ascensor-chino.json"
MAX_VALIDITY_DAYS = 397


@dataclass(frozen=True)
class CertificateProfile:
    name: str
    subject_cn: str
    dns_names: tuple[str, ...]
    validity_days: int
    allowed_dns_suffixes: tuple[str, ...]


def load_profile(path: Path = PROFILE_PATH) -> CertificateProfile:
    """Load editable defaults and scope restrictions from a JSON lab profile."""
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        profile = CertificateProfile(
            name=str(data["name"]),
            subject_cn=str(data["subject_cn"]),
            dns_names=tuple(str(item) for item in data["dns_names"]),
            validity_days=int(data["validity_days"]),
            allowed_dns_suffixes=tuple(str(item).lower() for item in data["allowed_dns_suffixes"]),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load certificate profile {path}: {exc}") from exc

    if not profile.allowed_dns_suffixes:
        raise ValueError("A lab profile must define at least one allowed DNS suffix.")
    if not 1 <= profile.validity_days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"Profile validity must be between 1 and {MAX_VALIDITY_DAYS} days.")
    validate_dns_names(profile.dns_names, profile.allowed_dns_suffixes)
    if profile.subject_cn.lower() not in {name.lower() for name in profile.dns_names}:
        raise ValueError("The profile Subject CN must also appear in its SAN DNS names.")
    return profile


def _normalize_dns_name(value: str) -> str:
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or "*" in name:
        raise ValueError(f"Invalid DNS name: {value!r}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid DNS name: {value!r}") from exc
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"Invalid DNS name: {value!r}")
    return ascii_name


def validate_dns_names(names: tuple[str, ...] | list[str], allowed_suffixes: tuple[str, ...]) -> list[str]:
    """Validate DNS SAN values and enforce the selected lab profile's suffix scope."""
    if not names:
        raise ValueError("At least one SAN DNS name is required.")
    normalized: list[str] = []
    for raw_name in names:
        name = _normalize_dns_name(raw_name)
        if not any(name.endswith(suffix) and name != suffix.lstrip(".") for suffix in allowed_suffixes):
            raise ValueError(
                f"{name} is outside this lab profile. Allowed DNS suffixes: {', '.join(allowed_suffixes)}"
            )
        if name not in normalized:
            normalized.append(name)
    return normalized


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
    output_dir: Path,
    allowed_dns_suffixes: tuple[str, ...],
) -> dict[str, Path]:
    """Verify the CA scalar, issue a scoped TLS certificate, and write outputs without overwriting."""
    ca_public = intermediate.public_key()
    if not isinstance(ca_public, ec.EllipticCurvePublicKey):
        raise ValueError("The supplied certificate does not contain an EC public key.")
    if private_scalar <= 0:
        raise ValueError("The private scalar must be a positive integer.")

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
    if not 1 <= validity_days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"Validity must be between 1 and {MAX_VALIDITY_DAYS} days.")

    try:
        ca_private = ec.derive_private_key(private_scalar, ca_public.curve)
    except (ValueError, OverflowError) as exc:
        raise ValueError("The supplied scalar is outside the valid range for this curve.") from exc
    if ca_private.public_key().public_numbers() != ca_public.public_numbers():
        raise ValueError("NO MATCH: the supplied scalar does not correspond to this CA certificate.")

    normalized_names = validate_dns_names(list(dns_names), allowed_dns_suffixes)
    normalized_cn = _normalize_dns_name(subject_cn)
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
                output.write(payloads[label])
            created.append(path)
        paths["key"].chmod(0o600)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return paths
