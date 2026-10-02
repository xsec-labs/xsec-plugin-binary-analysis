#!/usr/bin/env python3
"""Package the platform runtime for Factory ingestion."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

from engine_bundle_packaging import stage_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--radare2-prefix", required=True, type=Path)
    parser.add_argument("--radare2-source", required=True, type=Path)
    parser.add_argument("--r2ghidra-source", required=True, type=Path)
    parser.add_argument("--sleigh-dir", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        output = stage_bundle(arguments)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.error(str(error))
    print(f"engine_bundle.packaged path={output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
