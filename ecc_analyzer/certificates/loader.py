"""X.509 certificate loading helpers independent of terminal presentation."""

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


def load_certificate(path: Path) -> x509.Certificate:
    """Load a PEM or DER X.509 certificate containing an EC public key."""
    data = Path(path).read_bytes()
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"Could not parse an X.509 certificate: {exc}") from exc

    if not isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
        raise ValueError("The certificate does not contain an EC public key.")
    return cert
