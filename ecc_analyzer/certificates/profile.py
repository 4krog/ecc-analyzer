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


def load_profile(path: Path | None = None) -> CertificateProfile:
    """Load a strictly validated JSON profile for an authorized lab."""
    profile_path = Path(path) if path is not None else DEFAULT_PROFILE_PATH
    try:
        data: Any = json.loads(profile_path.read_text(encoding="utf-8"))
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
        raw_suffixes = tuple(item.lower() for item in data["allowed_dns_suffixes"])
        if any(not item.startswith(".") or item.startswith("..") for item in raw_suffixes):
            raise ValueError("Each allowed DNS suffix must start with exactly one dot.")
        suffixes = tuple("." + _normalize_dns_name(item[1:]) for item in raw_suffixes)
        profile = CertificateProfile(
            name=data["name"].strip(),
            subject_cn=data["subject_cn"].strip(),
            dns_names=tuple(data["dns_names"]),
            validity_days=data["validity_days"],
            allowed_dns_suffixes=suffixes,
        )
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load certificate profile {profile_path}: {exc}") from exc

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
