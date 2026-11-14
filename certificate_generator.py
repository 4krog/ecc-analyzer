"""Backward-compatible import for certificate issuance.

New code should import from :mod:`ecc_analyzer.certificates`.
"""

from ecc_analyzer.certificates.issuer import MAX_VALIDITY_DAYS, generate_server_certificate

__all__ = ["MAX_VALIDITY_DAYS", "generate_server_certificate"]
