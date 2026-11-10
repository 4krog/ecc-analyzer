#!/usr/bin/env python3
"""Compatibility launcher for running ECC Analyzer from a source checkout."""

from ecc_analyzer.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
