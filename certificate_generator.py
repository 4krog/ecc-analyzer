"""Backward-compatible imports for certificate generation.

New code should import from :mod:`ecc_analyzer.certificates`.
"""

from ecc_analyzer.certificates.profile import (
    CertificateProfile,
    DEFAULT_PROFILE_PATH,
    MAX_VALIDITY_DAYS,
    load_profile,
    validate_dns_names,
)
from ecc_analyzer.certificates.issuer import generate_server_certificate

__all__ = [
    "CertificateProfile", "DEFAULT_PROFILE_PATH", "MAX_VALIDITY_DAYS",
    "load_profile", "validate_dns_names", "generate_server_certificate",
]
