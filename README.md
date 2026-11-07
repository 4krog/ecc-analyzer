# ECC Analyzer

A lightweight command-line utility to inspect X.509 certificates containing elliptic-curve (EC) public keys and test explicitly supplied private-key candidates against those public keys.

**Version:** 1.0.0

## What it does

- Loads X.509 certificates in PEM or DER format.
- Displays certificate metadata and EC public-key parameters.
- Accepts one candidate, a list of candidates from a text file, or a bounded numeric range.
- Derives the public point for each candidate on the certificate's curve and compares it with the certificate public key.
- Offers an interactive terminal menu.

## What it does not do

- It does not recover arbitrary private keys or break ECDSA/ECC.
- It does not brute-force the full key space.
- It does not connect to remote hosts, scan networks, or exploit services.
- It does not validate certificate trust chains, revocation status, or hostname matching.

A match means only that the supplied integer derives the public key contained in the certificate. This is useful for demonstrating the danger of weak, predictable, or improperly generated private keys. It does not imply a weakness in the elliptic curve itself.

## Requirements

- Python 3.10 or newer.
- `cryptography` 42.0.0 or newer.

## Installation

It is recommended to use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Inspect a certificate:

```bash
python ecc-analyzer.py certificate.pem --inspect
```

Test one decimal candidate:

```bash
python ecc-analyzer.py certificate.pem --key 1234
```

Test a hexadecimal candidate:

```bash
python ecc-analyzer.py certificate.pem --key 0x4d2
```

Test candidates from a file (one value per line; lines may contain comments beginning with `#`):

```text
# Example candidate list
1
2
0x10
1234
```

```bash
python ecc-analyzer.py certificate.pem --candidates candidates.txt
```

Test an inclusive numeric range:

```bash
python ecc-analyzer.py certificate.pem --range 1:1000
```

The range mode is limited to 100,000 candidates to prevent accidental oversized runs.

Run without a mode to open the interactive menu:

```bash
python ecc-analyzer.py certificate.pem
```

## Exit codes

- `0`: inspection completed or at least one candidate matched.
- `1`: candidate testing completed, but no candidate matched.
- `2`: input, certificate, or usage error.

## Security and responsible use

Use this utility only with certificates and systems you own or are explicitly authorized to assess. Candidate testing should be restricted to controlled research and training environments. Never use intentionally weak test keys in production.

## Technical note

For a candidate private scalar `d), the tool derives the corresponding elliptic-curve public point `Q = d · G` using the curve declared by the certificate, then compares the resulting public numbers with the certificate's public key. It does not attempt to solve the elliptic-curve discrete logarithm problem.

## License

MIT. See [LICENSE](LICENSE).
