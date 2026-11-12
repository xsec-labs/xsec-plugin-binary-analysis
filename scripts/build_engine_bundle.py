#!/usr/bin/env python3
"""Build and package one native radare2 and r2ghidra runtime."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from dedupe_radare2_plugin_config import seed_no_gpl_plugin_config

R2_COMMIT = "ad27058877024389292fddf12e1db6e13824ba34"
R2GHIDRA_COMMIT = "1b5cba403c4c8751db8434f6790d5e0f132038f4"
R2_VERSION = "6.2.2"
SOURCES = {
    "radare2": ("https://github.com/radareorg/radare2.git", R2_COMMIT),
    "r2ghidra": ("https://github.com/radareorg/r2ghidra.git", R2GHIDRA_COMMIT),
}
TARGETS = {
    "aarch64-apple-darwin": ("darwin", frozenset({"arm64", "aarch64"})),
    "x86_64-apple-darwin": ("darwin", frozenset({"x86_64", "amd64"})),
    "x86_64-unknown-linux-gnu": ("linux", frozenset({"x86_64", "amd64"})),
    "x86_64-pc-windows-msvc": ("windows", frozenset({"x86_64", "amd64"})),
}


def run(arguments: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, cwd=cwd, env=env, check=True)


def host_os() -> str:
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    if os.name == "nt":
        return "windows"
    raise ValueError("engine builds support only macOS, Linux, and Windows")


def require_native_target(target: str) -> None:
    expected_os, architectures = TARGETS[target]
    machine = platform.machine().casefold()
    if host_os() != expected_os or machine not in architectures:
        raise ValueError(f"engine target {target} does not match this native build host")


def checkout_source(name: str, source_root: Path) -> Path:
    url, commit = SOURCES[name]
    destination = source_root / name
    destination.mkdir()
    run(["git", "init", "--quiet"], destination)
    # Pinned digests and the radare2 patch expect the upstream LF bytes.
    run(["git", "config", "core.autocrlf", "false"], destination)
    run(["git", "remote", "add", "origin", url], destination)
    run(["git", "fetch", "--depth=1", "--no-tags", "origin", commit], destination)
    run(["git", "checkout", "--detach", "FETCH_HEAD"], destination)
    actual = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=destination, check=True, capture_output=True, text=True
    ).stdout.strip()
    if actual != commit:
        raise ValueError(f"checked-out {name} source does not match the approved commit")
    return destination


def apply_radare2_patch(source: Path, patch_file: Path) -> None:
    git_apply = ["git", "-C", str(source), "apply"]
    run([*git_apply, "--check", str(patch_file)], source)
    run([*git_apply, str(patch_file)], source)


def radare2_configure_command(prefix: Path, os_name: str | None = None) -> list[str]:
    """Return radare2's acr configure command for one host.

    Under MSYS2 the build host is mingw64_nt-*, which radare2's configure does
    not map to an OS type (it knows only mingw32_nt), so make stops with
    "Unknown platform". Name the Windows OS type explicitly, as radare2's own
    sys/mingw64.sh does.
    """
    command = ["./configure", "--without-gpl", f"--prefix={prefix}"]
    if (os_name or host_os()) == "windows":
        command = ["sh", "configure", "--with-ostype=windows", *command[1:]]
    return command


def radare2_environment(os_name: str | None = None) -> dict[str, str]:
    """Return the radare2 configure and make environment for one host.

    radare2's make build compiles Windows sources with -DUNICODE, where
    r_sys_whoami passes a char buffer to GetUserName (GetUserNameW). GCC 14
    and later reject that as an incompatible pointer type, so keep it a
    warning on Windows only, and make MSYS create real symlinks.
    """
    environment = os.environ.copy()
    if (os_name or host_os()) == "windows":
        existing = environment.get("CFLAGS", "").strip()
        environment["CFLAGS"] = f"{existing} -Wno-error=incompatible-pointer-types".strip()
        # `make install` runs `rm -f last && ln -fs 6.2.2 last` twice. MSYS ln
        # copies directories by default, so the second rm fails on the copy.
        msys = environment.get("MSYS", "").strip()
        environment["MSYS"] = f"{msys} winsymlinks:nativestrict".strip()
    return environment


def configure_radare2(source: Path, prefix: Path) -> None:
    seed_no_gpl_plugin_config(source)
    run(radare2_configure_command(prefix), source, radare2_environment())
    helper = Path(__file__).with_name("dedupe_radare2_plugin_config.py")
    run([sys.executable, str(helper), "--source", str(source)], source)


MRI_AR_WRAPPER = """#!/bin/sh
# radare2 writes MSYS paths such as /d/a/... into the MRI script that it feeds
# to `ar -M`. The native UCRT64 ar cannot open them, so convert absolute addlib
# paths to Windows paths first. Every other ar call passes through unchanged.
if [ "$1" = "-M" ]; then
  # Build the whole script first: GNU ar ignores a malformed `addlib` line and
  # still exits 0, so a cygpath failure must stop the build here.
  script=$(while IFS= read -r line; do
    case "$line" in
      "addlib /"*)
        path=$(cygpath -m "${line#addlib }") || exit 1
        printf 'addlib %s\\n' "$path" ;;
      *) printf '%s\\n' "$line" ;;
    esac
  done) || exit 1
  printf '%s\\n' "$script" | ar "$@"
else
  exec ar "$@"
fi
"""


def radare2_make_arguments(work_root: Path, os_name: str | None = None) -> list[str]:
    """Return extra make arguments radare2 needs on one host.

    On Windows radare2 archives libr_shlr.lib with `ar -M` and an MRI script
    whose absolute entries (subprojects/zydis/libzydis.a) are MSYS paths, which
    the native ar reports as missing. Route ar through a wrapper that converts
    those paths with cygpath.
    """
    if (os_name or host_os()) != "windows":
        return []
    wrapper = work_root / "radare2-mri-ar.sh"
    wrapper.write_text(MRI_AR_WRAPPER, encoding="utf-8", newline="\n")
    return [f"AR=sh {wrapper.as_posix()}"]


def build_radare2(source: Path, prefix: Path, jobs: int, work_root: Path) -> None:
    make = shutil.which("gmake") or shutil.which("make")
    if make is None:
        raise ValueError("radare2 engine build requires GNU make or make")
    environment = radare2_environment()
    arguments = radare2_make_arguments(work_root)
    run([make, f"-j{jobs}", *arguments], source, environment)
    run([make, "install", *arguments], source, environment)


def engine_environment(prefix: Path) -> dict[str, str]:
    environment = os.environ.copy()
    binary_dir = prefix / "bin"
    environment["R2_LIBR_PLUGINS"] = str(prefix / "lib" / "radare2" / R2_VERSION)
    environment["PATH"] = str(binary_dir) + os.pathsep + environment.get("PATH", "")
    environment["PKG_CONFIG_PATH"] = str(prefix / "lib" / "pkgconfig")
    environment["R2_PREFIX"] = str(prefix)
    for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        environment[variable] = str(prefix / "lib")
    return environment


GHIDRA_MINGW_COMPAT = """/* Forced include for r2ghidra C++ sources under MinGW GCC (see
 * r2ghidra_environment). Declare the CRT isatty first, then rename the
 * static isatty stub that the flex scanner slghscan.cc defines under _WIN32
 * (always set by MinGW) so it no longer conflicts with MinGW's io.h. */
#ifndef XSEC_GHIDRA_MINGW_COMPAT_H
#define XSEC_GHIDRA_MINGW_COMPAT_H
#include <io.h>
#define isatty xsec_ghidra_scanner_isatty
#endif
"""


# Meson places LDFLAGS before the objects, so winpthread is pulled in whole
# rather than by reference; the import library is then never needed.
WINDOWS_STATIC_RUNTIME = (
    "-static-libgcc -static-libstdc++ "
    "-Wl,-Bstatic,--whole-archive,-lwinpthread,--no-whole-archive,-Bdynamic"
)


def write_ghidra_mingw_compat(work_root: Path) -> Path:
    header = work_root / "ghidra-mingw-compat.h"
    header.write_text(GHIDRA_MINGW_COMPAT, encoding="utf-8", newline="\n")
    return header


def r2ghidra_environment(
    prefix: Path, os_name: str | None = None, compat_header: Path | None = None
) -> dict[str, str]:
    """Return the r2ghidra build environment for one host.

    r2ghidra builds its ghidra-native archives as C++20 but links sleighc as
    C++14. When the C++14 objects are compiled without _GLIBCXX_ASSERTIONS
    (Meson before 1.4, such as Ubuntu 24.04's 1.3.2, or any Meson with
    b_ndebug=true), they reference std::string members that libstdc++ exports
    through extern templates. The C++20 archive members
    carry weak copies of those members, and GNU ld pulls the first such member
    (sleigh_arch.o, grammar.o) into sleighc before libstdc++ is searched. Those
    members need the decompiler library, which sleighc does not link, and the
    link fails with undefined ghidra::Architecture and TypeFactory symbols.
    Meson places LDFLAGS ahead of the linked archives, so naming libstdc++
    there resolves the references from the shared library instead.

    On Windows r2ghidra defines _WINDOWS only for MSVC. Under MinGW GCC the
    Ghidra sources then take their POSIX branches (dirent d_type in
    filemanage.cc), which MinGW lacks, so define it for the Win32 branches.
    The flex scanner also defines a static isatty stub under _WIN32 that
    clashes with MinGW's io.h, which the forced compat header resolves.

    Windows links the GCC runtime (libgcc, libstdc++, winpthread) statically
    so the engine ships no toolchain DLLs: they are unpinned MSYS2 builds
    under licenses the engine inventory does not carry.
    """
    environment = engine_environment(prefix)
    host = os_name or host_os()
    if host == "linux":
        existing = environment.get("LDFLAGS", "").strip()
        environment["LDFLAGS"] = f"-lstdc++ {existing}".strip()
    elif host == "windows":
        if compat_header is None:
            raise ValueError("Windows r2ghidra builds require the MinGW compat header")
        existing = environment.get("CXXFLAGS", "").strip()
        environment["CXXFLAGS"] = f"{existing} -D_WINDOWS -include {compat_header.as_posix()}".strip()
        existing = environment.get("LDFLAGS", "").strip()
        environment["LDFLAGS"] = f"{WINDOWS_STATIC_RUNTIME} {existing}".strip()
    return environment


def build_r2ghidra(source: Path, prefix: Path, work_root: Path, jobs: int) -> None:
    build = work_root / "r2ghidra-build"
    build.mkdir()
    compat_header = write_ghidra_mingw_compat(work_root) if host_os() == "windows" else None
    environment = r2ghidra_environment(prefix, compat_header=compat_header)
    run(
        [
            "meson",
            "setup",
            "--wrap-mode=forcefallback",
            "-Dzlib:default_library=static",
            f"--prefix={prefix}",
            "--libdir=lib",
            str(build),
            str(source),
        ],
        work_root,
        environment,
    )
    run(["meson", "compile", "-C", str(build), "-j", str(jobs)], work_root, environment)
    run(["meson", "install", "-C", str(build)], work_root, environment)


def verify_pins(radare2: Path, r2ghidra: Path) -> None:
    sys.path.insert(0, str(Path(__file__).parent))
    from source_pin_verification import verify_source_trees

    verify_source_trees(radare2, r2ghidra)


def package_engine(prefix: Path, radare2: Path, r2ghidra: Path, output: Path) -> None:
    helper = Path(__file__).with_name("package_engine_bundle.py")
    run(
        [
            sys.executable,
            str(helper),
            "--radare2-prefix",
            str(prefix),
            "--radare2-source",
            str(radare2),
            "--r2ghidra-source",
            str(r2ghidra),
            "--output",
            str(output),
        ],
        Path(__file__).resolve().parents[1],
        engine_environment(prefix),
    )


def build(target: str, work_root: Path, output: Path, jobs: int) -> None:
    require_native_target(target)
    work_root = work_root.resolve()
    output = output.resolve()
    if work_root.exists() or output.exists():
        raise ValueError("engine work and output paths must not already exist")
    work_root.mkdir(parents=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    source_root = work_root / "sources"
    source_root.mkdir()
    radare2 = checkout_source("radare2", source_root)
    r2ghidra = checkout_source("r2ghidra", source_root)
    patch_file = Path(__file__).resolve().parents[1] / "patches/radare2/0001-exclude-gpl-components-in-nogpl-build.patch"
    apply_radare2_patch(radare2, patch_file)
    prefix = work_root / "prefix"
    configure_radare2(radare2, prefix)
    build_radare2(radare2, prefix, jobs, work_root)
    build_r2ghidra(r2ghidra, prefix, work_root, jobs)
    verify_pins(radare2, r2ghidra)
    package_engine(prefix, radare2, r2ghidra, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 1, 4))
    arguments = parser.parse_args()
    if arguments.jobs < 1 or arguments.jobs > 64:
        parser.error("--jobs must be between 1 and 64")
    try:
        build(arguments.target, arguments.work_root, arguments.output, arguments.jobs)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.error(str(error))
    print(f"engine_bundle.built target={arguments.target} path={arguments.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
