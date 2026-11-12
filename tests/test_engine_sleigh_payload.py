from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_bundle_packaging import SLEIGH_SOURCE_SUFFIXES, copy_tree_files


class SleighPayloadTests(unittest.TestCase):
    def test_bundle_keeps_compiled_specs_and_drops_sleigh_sources(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-sleigh-") as directory:
            source = Path(directory) / "r2ghidra_sleigh"
            source.mkdir()
            runtime = ["x86-64.sla", "x86.ldefs", "x86-64.pspec", "x86-64-win.cspec", "x86.opinion", "x86-64.dwarf"]
            build_only = ["x86-64.slaspec", "avx.sinc"]
            for name in runtime + build_only:
                (source / name).write_bytes(name.encode())
            destination = Path(directory) / "bundle" / "sleigh"

            copy_tree_files(source, destination, excluded_suffixes=SLEIGH_SOURCE_SUFFIXES)

            self.assertEqual(sorted(path.name for path in destination.iterdir()), sorted(runtime))
            self.assertEqual((destination / "x86-64.sla").read_bytes(), b"x86-64.sla")


if __name__ == "__main__":
    unittest.main()
