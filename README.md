# ECC Analyzer

**BY 4KROG**

*Elliptic Curve Cryptography & Certificate Toolkit*

A lightweight interactive terminal utility to inspect X.509 certificates containing elliptic-curve (EC) public keys and test explicitly supplied private-key candidates.

**Version:** 1.2.0

## What it does

- Loads X.509 certificates in PEM or DER format.
- Displays certificate metadata and EC public-key parameters.
- Tests one candidate, a manually entered list, a candidate file, or a bounded numeric range.
- Derives the public point for each candidate on the certificate's curve and compares it with the certificate public key.
- After a supplied candidate matches the loaded EC public key, can issue a proof-of-impact TLS server certificate using that verified scalar.
- Uses Python's standard library for the terminal interface and `cryptography` for cryptographic operations.

## What it does not do

- It does not recover arbitrary private keys or break ECDSA/ECC.
- It does not brute-force the full key space.
- It does not connect to remote hosts, scan networks, or exploit services.
- It does not automatically validate a complete certificate trust chain, hostname trust, or revocation status.

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
python -m pip install .
```

This installs the reusable `ecc_analyzer` Python package and the `ecc-analyzer` terminal command. For development, install with `python -m pip install -e .`.

## Reusable Python API

The supported import surfaces are `ecc_analyzer.core` for candidate analysis and `ecc_analyzer.certificates` for certificate operations.

```python
from ecc_analyzer.core import parse_candidate, test_candidate, find_matching_candidates
from ecc_analyzer.certificates import load_certificate, generate_server_certificate
```

`test_candidate(public_key, candidate)` checks a supplied positive scalar against an EC public key. It does not discover or recover private keys.

## Usage

Start the interactive application:

```bash
ecc-analyzer
```

When running directly from a source checkout, the compatibility launcher also remains available:

```bash
python ecc-analyzer.py
```

The menu lets you:

1. Load and inspect a PEM or DER certificate.
2. Test one decimal or hexadecimal candidate.
3. Test a comma-separated manual list or load candidates from a text file.
4. Test an inclusive numeric range.
5. After a successful candidate match, generate a proof-of-impact TLS certificate signed by the loaded intermediate CA.

File prompts accept absolute paths, relative paths, and paths beginning with `~/`. Relative paths are resolved from the directory where you launched the program (the current working directory), not from the location of the script.

Candidate files accept one decimal or `0x`-prefixed hexadecimal value per line. Blank lines and comments beginning with `#` are ignored.

Numeric ranges use `START:END` and are limited to 100,000 candidates to prevent accidental oversized runs.

## Proof-of-impact certificate generation

Certificate generation is available only after a candidate has matched the public key of the currently loaded certificate. Loading another certificate clears that verified candidate. The scalar is retained in memory for the current session and is not written to the generated files. When a match is found, the CLI displays the matching scalar in the terminal; treat terminal output and scrollback as sensitive.

The generator asks for the Subject CN, SAN DNS names, validity period, and output directory. There are no JSON profiles or profile-specific defaults.

The generator accepts any syntactically valid DNS name; it does not impose a fixed suffix allowlist. If the issuing CA certificate contains DNS `NameConstraints`, those restrictions are enforced. The Subject CN must be included in the SAN list. Wildcard names are not accepted. Validity is limited to 397 days and is clipped to the CA certificate's expiry.

The generator checks that the loaded certificate is a currently valid CA with `BasicConstraints CA:TRUE` and `KeyUsage keyCertSign`. It enforces a CA EKU when present, verifies the candidate scalar against the CA's EC public key, creates a separate server key and CSR, and verifies the issued certificate signature before writing output. It refuses to overwrite existing output files.

The output directory contains:

- `server.key`: unencrypted server private key, created with filesystem mode `0600`.
- `server.csr`: certificate signing request.
- `server.crt`: issued leaf certificate.
- `fullchain.pem`: leaf certificate followed by the intermediate certificate (not the root).

**Important:** successful signature verification does not mean a browser or operating system will trust the certificate. This tool does not build or validate the complete chain to a trusted root, perform hostname verification, or check revocation. Test those properties separately in the authorized lab.

## Tests

Run the regression tests from the repository root:

```bash
python -m unittest discover -s tests -v
```

The tests create temporary EC CA certificates and temporary output files; they do not use production certificates or contact network services.

## Security and responsible use

Use this utility only with certificates and systems you own or are explicitly authorized to assess. Candidate testing and certificate issuance should be restricted to controlled research and training environments. Never use intentionally weak test keys in production.

Only matching candidate values are echoed in result messages. Treat candidate input, terminal scrollback, generated private keys, and local shell sessions as sensitive.

## Technical note

For a candidate private scalar `d`, the tool derives the corresponding elliptic-curve public point `Q = d · G` using the curve declared by the certificate, then compares the resulting public numbers with the certificate's public key. It does not attempt to solve the elliptic-curve discrete logarithm problem.

## License

MIT. See [LICENSE](LICENSE).
