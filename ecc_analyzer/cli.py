#!/usr/bin/env python3
"""4KROG ECC Analyzer: inspect X.509 EC certificates and test supplied candidates."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from datetime import timezone
from typing import Iterable

from cryptography import __version__ as cryptography_version
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from ecc_analyzer import __version__
from ecc_analyzer.certificates import generate_server_certificate
from ecc_analyzer.core.candidates import (
    parse_candidate,
    parse_range,
    read_candidates,
    test_candidate,
)
from ecc_analyzer.certificates.loader import load_certificate


VERSION = __version__

class Style:
    """Small ANSI styling helper; no third-party terminal UI dependency."""

    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    WHITE = "\033[97m"
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
        "███████╗  ██████╗  ██████╗",
        "██╔════╝ ██╔════╝ ██╔════╝",
        "█████╗   ██║      ██║",
        "██╔══╝   ██║      ██║",
        "███████╗ ╚██████╗ ╚██████╗",
        "╚══════╝  ╚═════╝  ╚═════╝",
    )
    print()
    for line in logo:
        print(Style.paint(line, Style.RED + Style.BOLD))
    print(Style.paint("          A N A L Y Z E R", Style.WHITE + Style.BOLD))
    print(Style.paint("             BY 4KROG", Style.RED + Style.BOLD))
    print(Style.paint("   Elliptic Curve Cryptography Toolkit", Style.DIM))
    print(Style.paint(f"                   v{VERSION}", Style.DIM))
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


def check_candidates(public_key: ec.EllipticCurvePublicKey, candidates: Iterable[int]) -> int | None:
    tested = 0
    matches = 0
    matching_scalar: int | None = None
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
            if matching_scalar is None:
                matching_scalar = candidate
            status = Style.paint("[MATCH]", Style.GREEN + Style.BOLD)
            candidate_label = Style.paint(f"Candidate #{tested}", Style.WHITE + Style.BOLD)
            private_key = Style.paint(str(candidate), Style.RED + Style.BOLD)
            print(f"  {status} {candidate_label} · Private key: {private_key} matches the certificate public key.")
        elif tested % 5000 == 0:
            print(Style.paint(f"  Tested {tested:,} candidates...", Style.DIM))

    print()
    if matches:
        print(Style.paint(f"  MATCH FOUND · {matches} matching candidate(s)", Style.GREEN + Style.BOLD))
    else:
        print(Style.paint("  NO MATCH · No supplied candidate matched.", Style.YELLOW + Style.BOLD))
    print(f"  Candidates tested: {tested:,}")
    print(Style.paint("  Only matching candidate values are displayed.", Style.DIM))
    return matching_scalar


def load_or_reuse_certificate(current_path: Path | None, current_cert: x509.Certificate | None):
    if current_cert is not None and current_path is not None:
        return current_path, current_cert
    path = ask_path()
    cert = load_certificate(path)
    print(Style.paint("\n  Certificate loaded successfully.", Style.GREEN))
    return path, cert


def generate_certificate_interactive(cert: x509.Certificate, private_scalar: int) -> None:
    print()
    separator()
    print(Style.paint("  PROOF-OF-IMPACT CERTIFICATE", Style.BOLD))
    separator()
    print(f"  Issuer        : {cert.subject.rfc4514_string()} (taken from loaded CA certificate)")
    subject_cn = input("  Subject CN: ").strip()
    raw_names = input("  SAN DNS names (comma-separated): ").strip()
    dns_names = [item.strip() for item in raw_names.split(",") if item.strip()]
    raw_days = input("  Validity days [7, maximum 397]: ").strip()
    validity_days = int(raw_days) if raw_days else 7
    output_raw = input("  Output directory [player-output]: ").strip() or "player-output"
    paths = generate_server_certificate(
        intermediate=cert,
        private_scalar=private_scalar,
        subject_cn=subject_cn,
        dns_names=dns_names,
        validity_days=validity_days,
        output_dir=normalize_path(output_raw),
    )
    print(Style.paint("\n  CERTIFICATE CREATED AND SIGNATURE VERIFIED", Style.GREEN + Style.BOLD))
    for label, path in paths.items():
        print(f"  {label:12}: {path}")
    print(Style.paint("  Note: this verifies the issued certificate signature, not client trust, hostname validation, or revocation.", Style.DIM))
    print(Style.paint("  DNS names must use the reserved .test namespace and satisfy CA NameConstraints.", Style.DIM))
    print(Style.paint("  The generated server private key is unencrypted; protect and delete it after the lab.", Style.YELLOW))


def main_menu() -> int:
    cert_path: Path | None = None
    cert: x509.Certificate | None = None
    verified_scalar: int | None = None
    banner()

    while True:
        print()
        print(Style.paint("  MAIN MENU", Style.BOLD))
        separator()
        print("  [1] Load / inspect certificate")
        print("  [2] Test single candidate")
        print("  [3] Test candidate list")
        print("  [4] Test numeric range")
        print("  [5] Generate proof-of-impact certificate")
        print("  [0] Exit")
        separator()
        if cert is not None and cert_path is not None:
            print(Style.paint(f"  LOADED: {cert_path}", Style.GREEN))
        else:
            print(Style.paint("  CERTIFICATE: NOT LOADED", Style.YELLOW))
        print(Style.paint(f"  ENGINE: Python + cryptography {cryptography_version}", Style.DIM))
        print(Style.paint("  MODE: LOCAL ANALYSIS", Style.DIM))
        if verified_scalar is not None:
            print(Style.paint("  VERIFIED CANDIDATE: AVAILABLE FOR THIS CERTIFICATE", Style.GREEN))
        else:
            print(Style.paint("  VERIFIED CANDIDATE: NONE", Style.DIM))
        choice = input("\n  4KROG > Select option: ").strip()

        try:
            if choice == "1":
                if cert is None:
                    replacement_path = ask_path()
                else:
                    replacement_raw = input("  Certificate path (Enter to keep current): ").strip()
                    if not replacement_raw:
                        inspect_certificate(cert, cert_path)
                        pause()
                        continue
                    replacement_path = normalize_path(replacement_raw)

                # A new certificate selection invalidates the previous match.
                verified_scalar = None

                # Load and inspect before committing the replacement.
                replacement_cert = load_certificate(replacement_path)
                inspect_certificate(replacement_cert, replacement_path)

                cert_path = replacement_path
                cert = replacement_cert
                print(Style.paint("\n  Certificate loaded successfully.", Style.GREEN))
                pause()
            elif choice == "2":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                public_key = cert.public_key()
                verified_scalar = None
                candidate = parse_candidate(input("  Private-key candidate (decimal or 0x hex): "))
                verified_scalar = check_candidates(public_key, [candidate])
                pause()
            elif choice == "3":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                public_key = cert.public_key()
                verified_scalar = None
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
                verified_scalar = check_candidates(public_key, candidates)
                pause()
            elif choice == "4":
                cert_path, cert = load_or_reuse_certificate(cert_path, cert)
                verified_scalar = None
                candidates = parse_range(input("  Range START:END: "))
                verified_scalar = check_candidates(cert.public_key(), candidates)
                pause()
            elif choice == "5":
                if cert is None:
                    raise ValueError("Load an intermediate CA certificate first.")
                if verified_scalar is None:
                    raise ValueError("Certificate generation is locked: verify a matching private-key candidate first.")
                generate_certificate_interactive(cert, verified_scalar)
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ECC Analyzer by 4KROG — inspect EC certificates and verify supplied private-key candidates."
    )
    parser.parse_args()
    try:
        return main_menu()
    except (KeyboardInterrupt, EOFError):
        print("\n\n  Session interrupted. Goodbye.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
