from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_bundle_packaging import copy_windows_dlls

# A stand-in for MinGW objdump -p: prints the "DLL Name:" lines listed for the
# image's basename in IMPORTS (one "name:dll,dll" entry per line).
FAKE_OBJDUMP = """#!/bin/sh
name="$(basename "$2")"
grep "^$name:" "$IMPORTS" | cut -d: -f2 | tr ',' '\\n' | sed '/^$/d; s/^/\\tDLL Name: /'
"""


@unittest.skipIf(os.name == "nt", "uses a POSIX shell stand-in for objdump")
class WindowsDllClosureTests(unittest.TestCase):
    def stage(self, root: Path, imports: dict[str, list[str]]) -> tuple[Path, list[Path], str, dict[str, str]]:
        output_prefix = root / "bundle" / "radare2"
        (output_prefix / "bin").mkdir(parents=True)
        (output_prefix / "plugins").mkdir()
        (output_prefix / "bin" / "r2.exe").write_bytes(b"MZ r2")
        (output_prefix / "plugins" / "core_ghidra.dll").write_bytes(b"MZ ghidra")
        prefix_lib = root / "prefix" / "lib"
        (prefix_lib / "core").mkdir(parents=True)
        (prefix_lib / "core" / "libr_core.dll").write_bytes(b"MZ core")
        (prefix_lib / "libr_core.dll").symlink_to("core/libr_core.dll")
        (prefix_lib / "libr_util.dll").write_bytes(b"MZ util")
        table = root / "imports.txt"
        table.write_text("".join(f"{name}:{','.join(dlls)}\n" for name, dlls in imports.items()))
        objdump = root / "objdump"
        objdump.write_text(FAKE_OBJDUMP)
        objdump.chmod(0o755)
        return output_prefix, [prefix_lib, root / "prefix" / "bin"], str(objdump), {"IMPORTS": str(table)}

    def test_copies_the_engine_import_closure_next_to_r2(self) -> None:
        imports = {
            "r2.exe": ["libr_core.dll", "KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"],
            "core_ghidra.dll": ["libr_core.dll", "WS2_32.dll"],
            "libr_core.dll": ["libr_util.dll", "kernel32.dll"],
            "libr_util.dll": ["ADVAPI32.dll"],
        }
        with tempfile.TemporaryDirectory(prefix="xsec-win-dlls-") as directory:
            output_prefix, search, objdump, environment = self.stage(Path(directory), imports)
            with mock.patch.dict(os.environ, environment):
                copied = copy_windows_dlls(output_prefix, search, objdump)
            self.assertEqual(sorted(copied), ["libr_core.dll", "libr_util.dll"])
            binary_dir = output_prefix / "bin"
            self.assertEqual((binary_dir / "libr_core.dll").read_bytes(), b"MZ core")
            self.assertFalse((binary_dir / "libr_core.dll").is_symlink())
            self.assertEqual((binary_dir / "libr_util.dll").read_bytes(), b"MZ util")
            self.assertFalse((binary_dir / "KERNEL32.dll").exists())

    def test_rejects_toolchain_runtime_dlls(self) -> None:
        for runtime in ("libstdc++-6.dll", "libgcc_s_seh-1.dll", "libwinpthread-1.dll"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory(prefix="xsec-win-dlls-") as directory:
                imports = {"r2.exe": ["libr_core.dll"], "core_ghidra.dll": [runtime], "libr_core.dll": []}
                output_prefix, search, objdump, environment = self.stage(Path(directory), imports)
                with mock.patch.dict(os.environ, environment), self.assertRaisesRegex(ValueError, re.escape(runtime)):
                    copy_windows_dlls(output_prefix, search, objdump)

    def test_rejects_an_import_it_cannot_find(self) -> None:
        imports = {"r2.exe": ["libmissing.dll"], "core_ghidra.dll": []}
        with tempfile.TemporaryDirectory(prefix="xsec-win-dlls-") as directory:
            output_prefix, search, objdump, environment = self.stage(Path(directory), imports)
            with mock.patch.dict(os.environ, environment), self.assertRaisesRegex(ValueError, "libmissing.dll"):
                copy_windows_dlls(output_prefix, search, objdump)


if __name__ == "__main__":
    unittest.main()
