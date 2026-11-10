"""Certificate profile loading and strict DNS scope validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_VALIDITY_DAYS = 397
DEFAULT_PROFILE_PATH = Path(__file__).resolve().parent / "profiles" / "default.json"


@dataclass(frozen=True)
class CertificateProfile:
    name: str
    subject_cn: str
    dns_names: tuple[str, ...]
    validity_days: int
    allowed_dns_suffixes: tuple[str, ...]


def load_profile(path: str | Path | None = None) -> CertificateProfile:
    """Load and validate a JSON certificate profile.

    If path is omitted, the package's generic .example.test profile is used.
    FileNotFoundError/OSError are preserved for filesystem failures;
    malformed JSON and invalid profile contents raise ValueError.
    A non-path-like path raises TypeError.
    """
    profile_path = Path(path) if path is not None else DEFAULT_PROFILE_PATH
    try:
        raw_data = profile_path.read_text(encoding="utf-8")
    except OSError:
        raise
    try:
        data: Any = json.loads(raw_data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse certificate profile {profile_path}: {exc}") from exc

    required = {"name", "subject_cn", "dns_names", "validity_days", "allowed_dns_suffixes"}
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError(f"Profile must contain exactly these fields: {', '.join(sorted(required))}")
    if not isinstance(data["name"], str) or not data["name"].strip():
        raise ValueError("Profile name must be a non-empty string.")
    if not isinstance(data["subject_cn"], str) or not data["subject_cn"].strip():
        raise ValueError("Profile subject_cn must be a non-empty string.")
    if not isinstance(data["dns_names"], list) or not data["dns_names"] or not all(isinstance(item, str) for item in data["dns_names"]):
        raise ValueError("Profile dns_names must be a non-empty list of strings.")
    if type(data["validity_days"]) is not int:
        raise ValueError("Profile validity_days must be an integer.")
    if not isinstance(data["allowed_dns_suffixes"], list) or not data["allowed_dns_suffixes"] or not all(isinstance(item, str) for item in data["allowed_dns_suffixes"]):
        raise ValueError("Profile allowed_dns_suffixes must be a non-empty list of strings.")

    suffixes = _normalize_dns_suffixes(tuple(data["allowed_dns_suffixes"]))
    profile = CertificateProfile(
        name=data["name"].strip(),
        subject_cn=data["subject_cn"].strip(),
        dns_names=tuple(data["dns_names"]),
        validity_days=data["validity_days"],
        allowed_dns_suffixes=suffixes,
    )
    if not 1 <= profile.validity_days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"Profile validity must be between 1 and {MAX_VALIDITY_DAYS} days.")
    normalized_names = validate_dns_names(profile.dns_names, profile.allowed_dns_suffixes)
    normalized_cn = _normalize_dns_name(profile.subject_cn)
    if normalized_cn not in normalized_names:
        raise ValueError("The profile Subject CN must also appear in its SAN DNS names.")
    return profile


def _normalize_dns_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("DNS names must be strings.")
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or "*" in name:
        raise ValueError(f"Invalid DNS name: {value!r}")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid DNS name: {value!r}") from exc
    if len(ascii_name) > 253:
        raise ValueError(f"Invalid DNS name (exceeds 253 ASCII characters): {value!r}")
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError(f"Invalid DNS name: {value!r}")
    return ascii_name


def _normalize_dns_suffixes(allowed_suffixes: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not isinstance(allowed_suffixes, (tuple, list)) or not allowed_suffixes:
        raise ValueError("At least one allowed DNS suffix is required.")
    normalized: list[str] = []
    for suffix in allowed_suffixes:
        if not isinstance(suffix, str):
            raise ValueError("Allowed DNS suffixes must be strings.")
        raw = suffix.strip()
        if not raw.startswith(".") or raw.startswith(".."):
            raise ValueError("Each allowed DNS suffix must start with exactly one dot.")
        value = "." + _normalize_dns_name(raw[1:])
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def validate_dns_names(
    names: tuple[str, ...] | list[str],
    allowed_suffixes: tuple[str, ...] | list[str],
) -> list[str]:
    """Normalize SAN DNS names and enforce the supplied suffix allowlist.

    Returns unique lowercase ASCII names. Raises ValueError for malformed
    names, invalid suffixes, empty input, or names outside the allowed scope.
    """
    if not isinstance(names, (tuple, list)) or not names:
        raise ValueError("At least one SAN DNS name is required.")
    suffixes = _normalize_dns_suffixes(allowed_suffixes)
    normalized: list[str] = []
    for raw_name in names:
        name = _normalize_dns_name(raw_name)
        if not any(name.endswith(suffix) for suffix in suffixes):
            raise ValueError(
                f"{name} is outside this lab profile. Allowed DNS suffixes: {', '.join(suffixes)}"
            )
        if name not in normalized:
            normalized.append(name)
    return normalized
