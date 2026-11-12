from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_engine_bundle import r2ghidra_environment

# A C++20 static archive whose first member also needs a symbol nothing
# provides, linked into a C++14 executable: the same shape as r2ghidra's
# libslgh.a (sleigh_arch.o, grammar.o) and sleighc.
ROOT_MESON = """project('engine-link-order', 'cpp', default_options: ['cpp_std=c++20'])
tool = subproject('archive', default_options: ['default_library=static']).get_variable('tool')
"""
ARCHIVE_MESON = """project('archive', 'cpp')
archive = static_library('archive', ['needs_decompiler.cc', 'strings.cc'])
tool = executable('tool', 'main.cc', link_with: archive, override_options: ['cpp_std=c++14'])
"""
NEEDS_DECOMPILER = """#include <string>
void decompiler_only();
std::size_t needs_decompiler(const std::string &s) { decompiler_only(); return s.size(); }
"""
STRINGS = """#include <string>
std::size_t string_length(const std::string &s) { return s.size() + (s.data() != nullptr); }
"""
MAIN = """#include <cstdio>
#include <string>
std::size_t string_length(const std::string &s);
int main() {
  std::string s = "sleigh";
  std::printf("%zu %zu %d\\n", string_length(s), s.size(), s.data()[0]);
  return 0;
}
"""


class R2GhidraEnvironmentTests(unittest.TestCase):
    def test_linux_links_libstdcxx_before_the_ghidra_archives(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-r2ghidra-env-") as directory:
            prefix = Path(directory)
            previous = os.environ.get("LDFLAGS")
            os.environ["LDFLAGS"] = "-L/opt/example/lib"
            try:
                environment = r2ghidra_environment(prefix, "linux")
            finally:
                if previous is None:
                    os.environ.pop("LDFLAGS", None)
                else:
                    os.environ["LDFLAGS"] = previous

            self.assertEqual(environment["LDFLAGS"], "-lstdc++ -L/opt/example/lib")
            self.assertEqual(environment["PKG_CONFIG_PATH"], str(prefix / "lib" / "pkgconfig"))

    def test_other_hosts_keep_the_engine_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-r2ghidra-env-") as directory:
            prefix = Path(directory)
            for os_name in ("darwin", "windows"):
                with self.subTest(os_name=os_name):
                    environment = r2ghidra_environment(prefix, os_name)
                    self.assertEqual(environment.get("LDFLAGS"), os.environ.get("LDFLAGS"))


@unittest.skipUnless(sys.platform.startswith("linux"), "the link-order failure is specific to GNU ld")
@unittest.skipUnless(shutil.which("meson") and shutil.which("ninja") and shutil.which("c++"), "needs meson, ninja and c++")
class R2GhidraLinkOrderBuildTests(unittest.TestCase):
    def test_mixed_standard_archive_links_with_the_r2ghidra_environment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xsec-r2ghidra-link-") as directory:
            root = Path(directory)
            source = root / "source"
            archive = source / "subprojects" / "archive"
            archive.mkdir(parents=True)
            (source / "meson.build").write_text(ROOT_MESON)
            (archive / "meson.build").write_text(ARCHIVE_MESON)
            (archive / "needs_decompiler.cc").write_text(NEEDS_DECOMPILER)
            (archive / "strings.cc").write_text(STRINGS)
            (archive / "main.cc").write_text(MAIN)
            build = root / "build"
            environment = r2ghidra_environment(root / "prefix", "linux")

            subprocess.run(["meson", "setup", str(build), str(source)], check=True, capture_output=True, env=environment)
            link_args = next(
                line
                for line in (build / "build.ninja").read_text().splitlines()
                if line.strip().startswith("LINK_ARGS") and "libarchive.a" in line
            )
            self.assertLess(link_args.index("-lstdc++"), link_args.index("libarchive.a"))

            compiled = subprocess.run(["ninja", "-C", str(build)], capture_output=True, text=True, env=environment)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            tool = build / "subprojects" / "archive" / "tool"
            self.assertEqual(subprocess.run([str(tool)], check=True, capture_output=True, text=True).stdout, "7 6 115\n")


if __name__ == "__main__":
    unittest.main()
