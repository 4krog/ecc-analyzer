"""Certificate profile loading and strict DNS scope validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

MAX_VALIDITY_DAYS = 397
DEFAULT_PROFILE_PATH = Path(__file__).resolve().parent / "profiles" / "default.json"

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
