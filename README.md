# 4KROG ECC Analyzer

A lightweight interactive terminal utility to inspect X.509 certificates containing elliptic-curve (EC) public keys and test explicitly supplied private-key candidates against those public keys.

**Version:** 1.1.0

## What it does

- Loads X.509 certificates in PEM or DER format.
- Displays certificate metadata and EC public-key parameters.
- Tests one candidate, a manually entered list, a candidate file, or a bounded numeric range.
- Derives the public point for each candidate on the certificate's curve and compares it with the certificate public key.
- Starts directly in an interactive terminal menu: no command-line arguments are required.
- Uses Python's standard library for the terminal interface and `cryptography` for cryptographic operations. No additional UI packages are required.

## What it does not do

- It does not recover arbitrary private keys or break ECDSA/ECC.
- It does not brute-force the full key space.
- It does not connect to remote hosts, scan networks, or exploit services.
- It does not validate certificate trust chains, revocation status, or hostname matching.

A match means only that the supplied integer derives the public key contained in the certificate. This demonstrates the danger of weak, predictable, or improperly generated private keys; it does not imply a weakness in the elliptic curve itself.

## Requirements

- Python 3.10 or newer.
- `cryptography` 42.0.0 or newer.

## Installation

It is recommended to use a virtual environment:

```bash
git clone https://github.com/4krog/ecc-analyzer.git
cd ecc-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Usage

Start the interactive application:

```bash
python ecc-analyzer.py
```

The menu lets you:

1. Load and inspect a PEM or DER certificate.
2. Test one decimal or hexadecimal candidate.
3. Test a comma-separated manual list or load candidates from a text file.
4. Test an inclusive numeric range.
5. Run a guided analysis session.

Candidate files accept one decimal or `0x`-prefixed hexadecimal value per line. Blank lines and comments beginning with `#` are ignored.

Numeric ranges use `START:END` and are limited to 100,000 candidates to prevent accidental oversized runs.

## Terminal presentation

The interface uses standard ANSI terminal colors when output is connected to a terminal. Set `NO_COLOR` to disable color output. No third-party terminal UI library is used.

## Security and responsible use

Use this utility only with certificates and systems you own or are explicitly authorized to assess. Candidate testing should be restricted to controlled research and training environments. Never use intentionally weak test keys in production.

Candidate values are not echoed in result messages. Treat candidate input, terminal scrollback, and local shell sessions as sensitive regardless.

## Technical note

For a candidate private scalar `d`, the tool derives the corresponding elliptic-curve public point `Q = d · G` using the curve declared by the certificate, then compares the resulting public numbers with the certificate's public key. It does not attempt to solve the elliptic-curve discrete logarithm problem.

## License

MIT. See [LICENSE](LICENSE).
