"""Candidate parsing and mathematical verification primitives.

This module contains no terminal UI and can be reused by other frontends.
It verifies supplied candidates; it does not recover arbitrary private keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric import ec


MAX_RANGE_CANDIDATES = 100_000


def parse_candidate(value: str) -> int:
    """Parse a positive decimal or 0x-prefixed hexadecimal scalar candidate."""
    if not isinstance(value, str):
        raise ValueError("Candidate must be supplied as text.")
    text = value.strip().replace("_", "")
    if not text:
        raise ValueError("Empty candidate.")
    try:
        number = int(text, 0) if text.lower().startswith(("0x", "+0x", "-0x")) else int(text, 10)
    except ValueError as exc:
        raise ValueError("Use a decimal integer or a 0x-prefixed hexadecimal value.") from exc
    if number <= 0:
        raise ValueError("A private-key candidate must be a positive integer.")
    return number


def test_candidate(public_key: ec.EllipticCurvePublicKey, candidate: int) -> bool:
    """Return whether candidate * G equals the supplied EC public point."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("public_key must be an elliptic-curve public key.")
    # bool is an int subclass in Python, but it is not a valid scalar input.
    if type(candidate) is not int or candidate <= 0:
        return False
    try:
        derived = ec.derive_private_key(candidate, public_key.curve).public_key()
    except (ValueError, OverflowError):
        return False
    return derived.public_numbers() == public_key.public_numbers()


def read_candidates(path: Path) -> list[int]:
    """Read decimal/hex candidates from a text file; ignore blanks and # comments."""
    path = Path(path)
    candidates: list[int] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            candidates.append(parse_candidate(value))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    if not candidates:
        raise ValueError("The candidate file contains no usable values.")
    return candidates


def parse_range(spec: str, maximum: int = MAX_RANGE_CANDIDATES) -> range:
    """Parse an inclusive START:END range with a defensive candidate-count limit."""
    if type(maximum) is not int or maximum < 1:
        raise ValueError("Range maximum must be a positive integer.")
    try:
        start_text, end_text = spec.split(":", 1)
        start = parse_candidate(start_text)
        end = parse_candidate(end_text)
    except (AttributeError, ValueError) as exc:
        raise ValueError("Range must use START:END, for example 1:1000.") from exc
    if end < start:
        raise ValueError("Range END must be greater than or equal to START.")
    count = end - start + 1
    if count > maximum:
        raise ValueError(f"Range contains {count:,} values; limit is {maximum:,}.")
    return range(start, end + 1)


def find_matching_candidates(
    public_key: ec.EllipticCurvePublicKey,
    candidates: Iterable[int],
) -> tuple[int, ...]:
    """Return unique valid integer candidates whose derived point matches public_key.

    Non-integer candidate values are ignored. Invalid public-key objects raise ValueError.
    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("public_key must be an elliptic-curve public key.")
    matches: list[int] = []
    seen: set[int] = set()
    for candidate in candidates:
        if type(candidate) is not int:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        if test_candidate(public_key, candidate):
            matches.append(candidate)
    return tuple(matches)
