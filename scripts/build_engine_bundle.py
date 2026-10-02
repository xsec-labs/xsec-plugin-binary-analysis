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


def configure_radare2(source: Path, prefix: Path) -> None:
    seed_no_gpl_plugin_config(source)
    command = ["./configure", "--without-gpl", f"--prefix={prefix}"]
    if os.name == "nt":
        command = ["sh", "configure", *command[1:]]
    run(command, source)
    helper = Path(__file__).with_name("dedupe_radare2_plugin_config.py")
    run([sys.executable, str(helper), "--source", str(source)], source)


def build_radare2(source: Path, prefix: Path, jobs: int) -> None:
    make = shutil.which("gmake") or shutil.which("make")
    if make is None:
        raise ValueError("radare2 engine build requires GNU make or make")
    run([make, f"-j{jobs}"], source)
    run([make, "install"], source)


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


def build_r2ghidra(source: Path, prefix: Path, work_root: Path, jobs: int) -> None:
    build = work_root / "r2ghidra-build"
    build.mkdir()
    environment = engine_environment(prefix)
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
    build_radare2(radare2, prefix, jobs)
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
