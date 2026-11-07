#!/usr/bin/env python3
"""4KROG ECC Analyzer: inspect X.509 EC certificates and test supplied candidates."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from datetime import timezone
from typing import Iterable

from cryptography import __version__ as cryptography_version
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


VERSION = "1.1.4"
MAX_RANGE_CANDIDATES = 100_000


class Style:
    """Small ANSI styling helper; no third-party terminal UI dependency."""

    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def paint(cls, value: str, color: str) -> str:
        if not cls.enabled:
            return value
        return f"{color}{value}{cls.RESET}"


def banner() -> None:
    logo = (
        "  #  #  # ####  ###  ###",
        " # # # # #   ##   ##    ",
        "#  # ##  #### #   ## ###",
        "##### # # # #  #   ##   #",
        "   # #  # #  #  ###  ### ",
    )
    print()
    for line in logo:
        print(Style.paint(line, Style.RED + Style.BOLD))
    print()
    print(Style.paint(f"       ECC ANALYZER v{VERSION}", Style.BOLD))
    print(Style.paint("       Elliptic Curve Key Analyzer", Style.DIM))
    print()


def separator() -> None:
    print(Style.paint("─" * 58, Style.DIM))


def pause() -> None:
    input("\nPress Enter to continue...")


def normalize_path(raw: str) -> Path:
    """Expand ~ and resolve relative paths from the current working directory."""
    return Path(raw.strip()).expanduser().resolve()


def ask_path(prompt: str = "Certificate path: ") -> Path:
    raw = input(prompt).strip()
    if not raw:
        raise ValueError("A file path is required.")
    return normalize_path(raw)


def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
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


def certificate_time_utc(cert: x509.Certificate, utc_attribute: str, legacy_attribute: str):
    """Return certificate validity time as an aware UTC datetime across cryptography versions."""
    value = getattr(cert, utc_attribute, None)
    if value is None:
        # Older cryptography releases expose naive datetimes documented as UTC.
        value = getattr(cert, legacy_attribute).replace(tzinfo=timezone.utc)
    return value


def inspect_certificate(cert: x509.Certificate, path: Path | None = None) -> ec.EllipticCurvePublicKey:
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("The certificate does not contain an EC public key.")

    numbers = public_key.public_numbers()
    separator()
    print(Style.paint("  CERTIFICATE INSPECTION", Style.BOLD))
    separator()
    if path:
        print(f"  File          : {path}")
    print(f"  Subject       : {cert.subject.rfc4514_string() or '(empty)'}")
    print(f"  Issuer        : {cert.issuer.rfc4514_string() or '(empty)'}")
    print(f"  Serial        : {cert.serial_number}")
    valid_from = certificate_time_utc(cert, "not_valid_before_utc", "not_valid_before")
    valid_until = certificate_time_utc(cert, "not_valid_after_utc", "not_valid_after")
    print(f"  Valid from    : {valid_from.isoformat()}")
    print(f"  Valid until   : {valid_until.isoformat()}")
    print(f"  Signature OID : {cert.signature_algorithm_oid.dotted_string}")
    print(f"  Public key    : EC / ECDSA")
    print(f"  Curve         : {public_key.curve.name}")
    print(f"  Key size      : {public_key.key_size} bits")
    print(f"  Public X      : {numbers.x:x}")
    print(f"  Public Y      : {numbers.y:x}")
    print(Style.paint("\n  Note: metadata display does not validate trust, hostname, or revocation.", Style.DIM))
    return public_key


def parse_candidate(value: str) -> int:
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
    try:
        derived = ec.derive_private_key(candidate, public_key.curve).public_key()
    except (ValueError, OverflowError):
        return False
    return derived.public_numbers() == public_key.public_numbers()


def check_candidates(public_key: ec.EllipticCurvePublicKey, candidates: Iterable[int]) -> bool:
    tested = 0
    matches = 0
    seen: set[int] = set()
    print()
    separator()
    print(Style.paint("  CANDIDATE VERIFICATION", Style.BOLD))
    separator()

    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        tested += 1
        if test_candidate(public_key, candidate):
            matches += 1
            status = Style.paint("[MATCH]", Style.GREEN + Style.BOLD)
            candidate_label = Style.paint(f"Candidate #{tested}", Style.WHITE + Style.BOLD)
            print(f"  {status} {candidate_label} matches the certificate public key.")
        elif tested % 5000 == 0:
            print(Style.paint(f"  Tested {tested:,} candidates...", Style.DIM))

    print()
    if matches:
        print(Style.paint(f"  MATCH FOUND · {matches} matching candidate(s)", Style.GREEN + Style.BOLD))
    else:
        print(Style.paint("  NO MATCH · No supplied candidate matched.", Style.YELLOW + Style.BOLD))
    print(f"  Candidates tested: {tested:,}")
    print(Style.paint("  Candidate values are not echoed to the terminal.", Style.DIM))
    return matches > 0


def read_candidates(path: Path) -> list[int]:
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


def parse_range(spec: str) -> range:
    try:
        start_text, end_text = spec.split(":", 1)
        start = parse_candidate(start_text)
        end = parse_candidate(end_text)
    except ValueError as exc:
        raise ValueError("Range must use START:END, for example 1:1000.") from exc
    if end < start:
        raise ValueError("Range END must be greater than or equal to START.")
    count = end - start + 1
    if count > MAX_RANGE_CANDIDATES:
        raise ValueError(f"Range contains {count:,} values; limit is {MAX_RANGE_CANDIDATES:,}.")
    return range(start, end + 1)


def load_or_reuse_certificate(current_path: Path | None, current_cert: x509.Certificate | None):
    if current_cert is not None and current_path is not None:
        return current_path, current_cert
    path = ask_path()
    cert = load_certificate(path)
    print(Style.paint("\n  Certificate loaded successfully.", Style.GREEN))
    return path, cert


def guided_analysis(path: Path | None, cert: x509.Certificate | None):
    path, cert = load_or_reuse_certificate(path, cert)
    public_key = inspect_certificate(cert, path)
    print("\n  Choose candidate source:")
    print("  [1] One candidate")
    print("  [2] Manual list (comma-separated)")
    print("  [3] Candidate file")
    print("  [4] Numeric range")
    choice = input("\n  Source > ").strip()

    if choice == "1":
        candidates = [parse_candidate(input("  Candidate (decimal or 0x hex): "))]
    elif choice == "2":
        raw = input("  Candidates (comma-separated): ")
        candidates = [parse_candidate(item) for item in raw.split(",") if item.strip()]
        if not candidates:
            raise ValueError("No candidates supplied.")
    elif choice == "3":
        candidate_path = ask_path("  Candidate file path: ")
        candidates = read_candidates(candidate_path)
    elif choice == "4":
        candidates = parse_range(input("  Range START:END: "))
    else:
        raise ValueError("Unknown candidate source.")
    check_candidates(public_key, candidates)
    return path, cert


def main_menu() -> int:
    cert_path: Path | None = None
    cert: x509.Certificate | None = None
    banner()

    while True:
        print()
        print(Style.paint("  MAIN MENU", Style.BOLD))
        separator()
        print("  [1] Load / inspect certificate")
        print("  [2] Test single candidate")
        print("  [3] Test candidate list")
        print("  [4] Test numeric range")
        print("  [5] Guided analysis")
        print("  [0] Exit")
        separator()
        if cert_path:
            print(Style.paint(f"  LOADED: {cert_path}", Style.GREEN))
        else:
            print(Style.paint("  CERTIFICATE: NOT LOADED", Style.YELLOW))
        print(Style.paint(f"  ENGINE: Python + cryptography {cryptography_version}", Style.DIM))
        print(Style.paint("  MODE: LOCAL ANALYSIS", Style.DIM))
        choice = input("\n  4KROG > Select option: ").strip()

        try:
            if choice == "1":
                if cert is None:
                    cert_path = ask_path()
                else:
                    replacement_path = input("  Certificate path (Enter to keep current): ").strip()
                    if replacement_path:
                        cert_path = normalize_path(replacement_path)
                if cert_path is None:
                    raise ValueError("No certificate selected.")
                cert = load_certificate(cert_path)
                inspect_certificate(cert, cert_path)
                pause()
            elif choice == "2":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                public_key = cert.public_key()
                candidate = parse_candidate(input("  Private-key candidate (decimal or 0x hex): "))
                check_candidates(public_key, [candidate])
                pause()
            elif choice == "3":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                public_key = cert.public_key()
                print("  [1] Enter candidates manually")
                print("  [2] Load candidates from file")
                source = input("  Source > ").strip()
                if source == "1":
                    raw = input("  Candidates (comma-separated): ")
                    candidates = [parse_candidate(item) for item in raw.split(",") if item.strip()]
                    if not candidates:
                        raise ValueError("No candidates supplied.")
                elif source == "2":
                    candidates = read_candidates(ask_path("  Candidate file path: "))
                else:
                    raise ValueError("Unknown candidate source.")
                check_candidates(public_key, candidates)
                pause()
            elif choice == "4":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                candidates = parse_range(input("  Range START:END: "))
                check_candidates(cert.public_key(), candidates)
                pause()
            elif choice == "5":
                cert_path, cert = guided_analysis(cert_path, cert)
                pause()
            elif choice == "0":
                print(Style.paint("\n  4KROG · Analysis session closed.\n", Style.DIM))
                return 0
            else:
                print(Style.paint("  [!] Unknown option.", Style.YELLOW))
                pause()
        except (OSError, ValueError) as exc:
            print(Style.paint(f"\n  [ERROR] {exc}", Style.RED + Style.BOLD))
            pause()


if __name__ == "__main__":
    try:
        raise SystemExit(main_menu())
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Session interrupted. Goodbye.")
        raise SystemExit(130)
