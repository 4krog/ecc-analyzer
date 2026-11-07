#!/usr/bin/env python3
"""Inspect X.509 EC certificates and test explicitly supplied private-key candidates."""

from __future__ import annotations

import argparse
import sys
from datetime import timezone
from pathlib import Path

from cryptography import __version__ as cryptography_version
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding


VERSION = "1.0.0"
MAX_RANGE_CANDIDATES = 100_000


def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ValueError(f"Could not parse an X.509 certificate: {exc}") from exc


def utc_datetime(value):
    # cryptography >= 42 exposes timezone-aware *_utc properties.
    return value


def format_name(name: x509.Name) -> str:
    return name.rfc4514_string() or "(empty)"


def inspect_certificate(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    public_key = cert.public_key()
    print("\n=== X.509 CERTIFICATE ===")
    print(f"Subject       : {format_name(cert.subject)}")
    print(f"Issuer        : {format_name(cert.issuer)}")
    print(f"Serial        : {cert.serial_number}")
    print(f"Valid from    : {cert.not_valid_before_utc.isoformat()}")
    print(f"Valid until   : {cert.not_valid_after_utc.isoformat()}")
    print(f"Signature OID : {cert.signature_algorithm_oid.dotted_string}")

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError(
            f"Certificate public key is {public_key.__class__.__name__}, not EC."
        )

    numbers = public_key.public_numbers()
    print(f"Public key    : Elliptic Curve")
    print(f"Curve         : {public_key.curve.name}")
    print(f"Key size      : {public_key.key_size} bits")
    print(f"Public X      : {numbers.x:x}")
    print(f"Public Y      : {numbers.y:x}")
    print("\nNote: this displays certificate metadata; it does not assess trust or validity.")
    return public_key


def parse_candidate(value: str) -> int:
    text = value.strip().replace("_", "")
    if not text:
        raise ValueError("Empty candidate")
    try:
        number = int(text, 0) if text.lower().startswith(("0x", "+0x", "-0x")) else int(text, 10)
    except ValueError as exc:
        raise ValueError(f"Invalid candidate {value!r}; use decimal or 0x-prefixed hex.") from exc
    if number <= 0:
        raise ValueError("A private-key candidate must be a positive integer.")
    return number


def test_candidate(public_key: ec.EllipticCurvePublicKey, candidate: int) -> bool:
    try:
        derived = ec.derive_private_key(candidate, public_key.curve).public_key()
    except (ValueError, OverflowError):
        return False
    return derived.public_numbers() == public_key.public_numbers()


def check_candidates(public_key, candidates: list[int]) -> bool:
    found = False
    seen = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if test_candidate(public_key, candidate):
            print(f"[MATCH] Candidate {candidate} (0x{candidate:x}) matches the certificate public key.")
            found = True
        else:
            print(f"[NO MATCH] Candidate {candidate} (0x{candidate:x})")
    if not found:
        print("[RESULT] No supplied candidate matched.")
    return found


def read_candidates(path: Path) -> list[int]:
    candidates = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            candidates.append(parse_candidate(value))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return candidates


def parse_range(spec: str) -> list[int]:
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
        raise ValueError(f"Range contains {count} values; limit is {MAX_RANGE_CANDIDATES:,}.")
    return list(range(start, end + 1))


def interactive(cert_path: Path, cert: x509.Certificate, public_key) -> int:
    while True:
        print("\n=== ECC ANALYZER ===")
        print(f"Certificate: {cert_path}")
        print("1) Inspect certificate")
        print("2) Test one candidate")
        print("3) Test candidates (comma-separated)")
        print("4) Test a numeric range")
        print("5) Load another certificate")
        print("0) Exit")
        choice = input("> ").strip()

        try:
            if choice == "1":
                inspect_certificate(cert)
            elif choice == "2":
                candidate = parse_candidate(input("Private-key candidate (decimal or 0x hex): "))
                check_candidates(public_key, [candidate])
            elif choice == "3":
                raw = input("Candidates, separated by commas: ")
                candidates = [parse_candidate(item) for item in raw.split(",") if item.strip()]
                if not candidates:
                    print("[!] No candidates supplied.")
                else:
                    check_candidates(public_key, candidates)
            elif choice == "4":
                candidates = parse_range(input("Range START:END (for example 1:1000): "))
                check_candidates(public_key, candidates)
            elif choice == "5":
                new_path = Path(input("Certificate path: ").strip()).expanduser()
                cert = load_certificate(new_path)
                cert_path = new_path
                public_key = inspect_certificate(cert)
            elif choice == "0":
                return 0
            else:
                print("[!] Unknown option.")
        except (OSError, ValueError) as exc:
            print(f"[ERROR] {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect an X.509 EC certificate and test supplied private-key candidates."
    )
    parser.add_argument("certificate", type=Path, help="Certificate in PEM or DER format")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--inspect", action="store_true", help="Print certificate details")
    group.add_argument("--key", help="Test one candidate (decimal or 0x-prefixed hexadecimal)")
    group.add_argument("--candidates", type=Path, help="Text file with one candidate per line")
    group.add_argument("--range", dest="candidate_range", help="Test an inclusive START:END range")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        cert = load_certificate(args.certificate.expanduser())
        public_key = inspect_certificate(cert) if args.inspect or not any(
            (args.key is not None, args.candidates is not None, args.candidate_range is not None)
        ) else cert.public_key()

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Certificate does not contain an EC public key.")

        if args.inspect:
            return 0
        if args.key is not None:
            matched = check_candidates(public_key, [parse_candidate(args.key)])
            return 0 if matched else 1
        if args.candidates is not None:
            matched = check_candidates(public_key, read_candidates(args.candidates.expanduser()))
            return 0 if matched else 1
        if args.candidate_range is not None:
            matched = check_candidates(public_key, parse_range(args.candidate_range))
            return 0 if matched else 1

        return interactive(args.certificate, cert, public_key)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
