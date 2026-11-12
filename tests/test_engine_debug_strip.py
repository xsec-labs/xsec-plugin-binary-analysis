from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import engine_portability
from engine_portability import strip_debug_symbols

LIBRARY = "int ghidra_answer(void) { return 42; }\n"
PROGRAM = "int ghidra_answer(void);\nint main(void) { return ghidra_answer() == 42 ? 0 : 1; }\n"


def section_names(image: Path) -> set[str]:
    output = subprocess.run(["readelf", "-S", "-W", str(image)], check=True, capture_output=True, text=True).stdout
    return {token for token in output.split() if token.startswith(".")}


def stage_engine(root: Path, binary: str) -> list[Path]:
    images = [
        root / "radare2" / "bin" / binary,
        root / "radare2" / "lib" / "libr_core.so.6.2.2",
        root / "radare2" / "plugins" / "core_ghidra.so",
        root / "radare2" / "bin" / "libr_util.dll",
    ]
    for image in images:
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(b"image")
    (root / "sleigh").mkdir()
    (root / "sleigh" / "x86.sla").write_bytes(b"data")
    return images


class StripCommandTests(unittest.TestCase):
    def test_each_platform_strips_its_executable_and_every_library(self) -> None:
        expectations = {"darwin": ("-S", "r2"), "linux": ("--strip-debug", "r2"), "windows": ("--strip-debug", "r2.exe")}
        for platform_key, (flag, binary) in expectations.items():
            with self.subTest(platform=platform_key), tempfile.TemporaryDirectory(prefix="xsec-strip-") as directory:
                root = Path(directory)
                images = stage_engine(root, binary)
                with mock.patch.object(engine_portability.shutil, "which", return_value="/usr/bin/strip"), mock.patch.object(
                    engine_portability.subprocess, "run"
                ) as run:
                    self.assertEqual(strip_debug_symbols(root, platform_key), len(images))
                commands = [call.args[0] for call in run.call_args_list]
                self.assertEqual(commands[0], ["/usr/bin/strip", flag, str(images[0])])
                self.assertEqual({command[2] for command in commands}, {str(image) for image in images})
                self.assertTrue(all(command[1] == flag for command in commands))

    def test_missing_strip_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-strip-") as directory, mock.patch.object(
            engine_portability.shutil, "which", return_value=None
        ):
            with self.assertRaisesRegex(ValueError, "requires strip"):
                strip_debug_symbols(Path(directory), "linux")


@unittest.skipUnless(sys.platform.startswith("linux"), "checks ELF debug sections")
@unittest.skipUnless(shutil.which("cc") and shutil.which("strip") and shutil.which("readelf"), "needs cc, strip and readelf")
class LinuxStripTests(unittest.TestCase):
    def test_linux_engine_images_lose_debug_sections_and_still_run(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-strip-elf-") as directory:
            root = Path(directory) / "bundle"
            source = Path(directory) / "source"
            source.mkdir()
            (source / "library.c").write_text(LIBRARY)
            (source / "program.c").write_text(PROGRAM)
            lib = root / "radare2" / "lib"
            plugins = root / "radare2" / "plugins"
            binary = root / "radare2" / "bin" / "r2"
            for path in (lib, plugins, binary.parent):
                path.mkdir(parents=True)
            library = lib / "libr_core.so.6.2.2"
            subprocess.run(["cc", "-g", "-shared", "-fPIC", "-o", str(library), str(source / "library.c")], check=True)
            shutil.copy2(library, plugins / "core_ghidra.so")
            subprocess.run(
                ["cc", "-g", "-o", str(binary), str(source / "program.c"), str(library), "-Wl,-rpath,$ORIGIN/../lib"],
                check=True,
            )
            images = [binary, library, plugins / "core_ghidra.so"]
            for image in images:
                self.assertIn(".debug_info", section_names(image))

            self.assertEqual(strip_debug_symbols(root, "linux"), 3)

            for image in images:
                sections = section_names(image)
                self.assertFalse({name for name in sections if name.startswith(".debug")}, image.name)
                self.assertIn(".dynsym", sections)
            subprocess.run([str(binary)], check=True)


class PatchCheckoutTests(unittest.TestCase):
    def test_patches_keep_their_committed_line_endings(self) -> None:
        patch = "patches/radare2/0001-exclude-gpl-components-in-nogpl-build.patch"
        result = subprocess.run(["git", "check-attr", "text", "--", patch], cwd=ROOT, check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), f"{patch}: text: unset")


if __name__ == "__main__":
    unittest.main()
