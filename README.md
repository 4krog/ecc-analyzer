# 4KROG ECC Analyzer

A lightweight interactive terminal utility to inspect X.509 certificates containing elliptic-curve (EC) public keys and test explicitly supplied private-key candidates against those public keys.

**Version:** 1.2.0

## What it does

- Loads X.509 certificates in PEM or DER format.
- Displays certificate metadata and EC public-key parameters.
- Tests one candidate, a manually entered list, a candidate file, or a bounded numeric range.
- Derives the public point for each candidate on the certificate's curve and compares it with the certificate public key.
- Starts directly in an interactive terminal menu: no command-line arguments are required.
- After a supplied candidate matches the loaded EC public key, can issue a lab-scoped TLS server certificate using that verified scalar.
- Uses Python's standard library for the terminal interface and `cryptography` for cryptographic operations. No additional UI packages are required.

## What it does not do

- It does not recover arbitrary private keys or break ECDSA/ECC.
- It does not brute-force the full key space.
- It does not connect to remote hosts, scan networks, or exploit services.
- It does not automatically validate a complete certificate trust chain, revocation status, or hostname matching.

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

The supported import surfaces are `ecc_analyzer.core` for candidate analysis and `ecc_analyzer.certificates` for certificate operations. Their exported names are explicit; internal modules may change without being part of the compatibility promise.

```python
from ecc_analyzer.core import parse_candidate, test_candidate, find_matching_candidates
from ecc_analyzer.certificates import load_certificate, load_profile
```

`test_candidate(public_key, candidate)` checks a supplied positive scalar against an EC public key. It does not discover or recover private keys. Certificate issuance is intended for authorized labs and enforces the selected profile's DNS suffix allowlist.


## Usage

Start the installed interactive application with the generic, reserved lab profile:

```bash
ecc-analyzer
```

When running directly from a source checkout, the compatibility launcher also remains available:

```bash
python ecc-analyzer.py
```

Select a different JSON profile explicitly:

```bash
ecc-analyzer --profile profiles/el-ascensor-chino.json
```

You can provide your own profile file with the same JSON structure. Use only DNS namespaces reserved for testing or domains you are explicitly authorized to assess. The profile's `allowed_dns_suffixes` setting is enforced when SAN names are entered.

The menu lets you:

1. Load and inspect a PEM or DER certificate.

File prompts accept absolute paths, relative paths, and paths beginning with `~/`. Relative paths are resolved from the directory where you launched the program (the current working directory), not from the location of the script.
2. Test one decimal or hexadecimal candidate.
3. Test a comma-separated manual list or load candidates from a text file.
4. Test an inclusive numeric range.
5. Run a guided analysis session.
6. After a successful candidate match, generate a proof-of-impact TLS certificate signed by the loaded intermediate CA.

Candidate files accept one decimal or `0x`-prefixed hexadecimal value per line. Blank lines and comments beginning with `#` are ignored.

Numeric ranges use `START:END` and are limited to 100,000 candidates to prevent accidental oversized runs.

## Proof-of-impact certificate generation

Option 6 is available only after a candidate has matched the public key of the currently loaded certificate. Loading another certificate clears that verified candidate. The scalar is retained only in the running process and is not exported.

The default profile is bundled inside the `ecc_analyzer` package and uses the reserved `.example.test` namespace. The challenge-specific `profiles/el-ascensor-chino.json` remains an external profile in a source checkout (or can be supplied from any path) and is selected explicitly with `--profile`.

A profile defines the display name, default Subject CN, default SAN DNS names, validity period, and allowed DNS suffixes. These values can be edited in the interactive prompts, but every SAN name must remain within the selected profile's configured suffix scope. Custom profiles should use reserved test namespaces or domains that you are explicitly authorized to assess. The Issuer is always taken from the loaded CA certificate; it is not an arbitrary text field.

The generator checks that the loaded certificate is a currently valid CA with `BasicConstraints CA:TRUE` and `KeyUsage keyCertSign`, verifies the candidate scalar against its EC public key, creates a separate server key and CSR, and verifies the issued certificate signature before writing output. It refuses to overwrite existing output files.

The output directory contains `server.key`, `server.csr`, `server.crt`, and `fullchain.pem`. The server private key is unencrypted PEM protected with filesystem mode `0600`; protect it as a secret. The generated full chain contains the leaf certificate and intermediate certificate, not the root certificate.

**Important:** successful signature verification does not mean a browser or operating system will trust the certificate. Trust-store installation, hostname validation, chain construction, validity, and revocation must be tested separately in the authorized lab.

## Tests

Run the regression tests from the repository root:

```bash
python -m unittest discover -s tests -v
```

The tests create temporary EC CA certificates and temporary output files; they do not use production certificates or contact network services.

## Terminal presentation

The interface uses standard ANSI terminal colors when output is connected to a terminal. Successful match status labels are bold green, candidate identifiers are bold bright white, and a matching private-key candidate is displayed in bold red; non-matches are bold yellow, and errors are bold red. Set `NO_COLOR` to disable color output. No third-party terminal UI library is used.

## Security and responsible use

Use this utility only with certificates and systems you own or are explicitly authorized to assess. Candidate testing should be restricted to controlled research and training environments. Never use intentionally weak test keys in production.

Only matching candidate values are echoed in result messages, in bold red. Treat candidate input, terminal scrollback, and local shell sessions as sensitive regardless.

## Technical note

For a candidate private scalar `d`, the tool derives the corresponding elliptic-curve public point `Q = d · G` using the curve declared by the certificate, then compares the resulting public numbers with the certificate's public key. It does not attempt to solve the elliptic-curve discrete logarithm problem.

## License

MIT. See [LICENSE](LICENSE).
