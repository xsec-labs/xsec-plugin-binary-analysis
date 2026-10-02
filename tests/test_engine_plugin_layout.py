from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from engine_portability import normalize_r2ghidra_plugin_name


class R2GhidraPluginLayoutTests(unittest.TestCase):
    def test_normalizes_the_pinned_library_name_for_each_platform(self) -> None:
        layouts = {
            "darwin": ("libcore_r2ghidra.dylib", "core_ghidra.dylib"),
            "linux": ("libcore_r2ghidra.so", "core_ghidra.so"),
            "windows": ("core_r2ghidra.dll", "core_ghidra.dll"),
        }
        for platform_key, (source_name, target_name) in layouts.items():
            with self.subTest(platform=platform_key), tempfile.TemporaryDirectory(
                prefix="xsec-r2ghidra-layout-"
            ) as directory:
                plugin_dir = Path(directory)
                source = plugin_dir / source_name
                source.write_bytes(b"r2ghidra-library")

                target = normalize_r2ghidra_plugin_name(plugin_dir, platform_key)

                self.assertEqual(target.name, target_name)
                self.assertFalse(source.exists())
                self.assertEqual(target.read_bytes(), b"r2ghidra-library")

    def test_rejects_ambiguous_plugin_libraries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-r2ghidra-ambiguous-") as directory:
            plugin_dir = Path(directory)
            (plugin_dir / "libcore_r2ghidra.dylib").write_bytes(b"one")
            (plugin_dir / "core_r2ghidra.dylib").write_bytes(b"two")

            with self.assertRaisesRegex(ValueError, "exactly one"):
                normalize_r2ghidra_plugin_name(plugin_dir, "darwin")


if __name__ == "__main__":
    unittest.main()
