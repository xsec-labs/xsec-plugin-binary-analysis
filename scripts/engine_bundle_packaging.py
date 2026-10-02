#!/usr/bin/env python3
"""Assemble a relocatable, auditable radare2 and r2ghidra engine bundle."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from engine_portability import BuildPathMap, normalize_build_paths, normalize_engine_plugin_assets, strip_macos_debug_symbols

ENGINE_VERSION = "6.2.2"
MAX_BUNDLE_BYTES = 100 * 1024 * 1024
MAX_BUNDLE_FILES = 4096
DYNAMIC_EXTENSIONS = (".dylib", ".dll")

def is_dynamic_library(path: Path) -> bool:
    name = path.name.casefold()
    return path.suffix.casefold() in DYNAMIC_EXTENSIONS or ".so" in name

def run_checked(arguments: list[str]) -> str:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError(f"engine packaging command failed: {Path(arguments[0]).name}")
    return result.stdout.strip()

def require_source_directory(path: Path, name: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"engine packaging input is not a directory: {name}")
    return resolved


def resolve_engine_binary(prefix: Path) -> Path:
    candidates = ("bin/r2.exe", "bin/r2", "bin/radare2.exe", "bin/radare2")
    for relative in candidates:
        candidate = prefix / relative
        if candidate.exists():
            resolved = candidate.resolve(strict=True)
            if not resolved.is_relative_to(prefix) or not resolved.is_file():
                raise ValueError("radare2 executable resolves outside its install prefix")
            return resolved
    raise ValueError("radare2 install prefix has no executable")


def copy_tree_files(source: Path, destination: Path, excluded: frozenset[str] = frozenset()) -> None:
    if not source.is_dir():
        raise ValueError(f"engine packaging directory is missing: {source.name}")
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        directories[:] = [
            name for name in directories
            if not (current_path / name).is_symlink()
            and (relative / name).as_posix() not in excluded
        ]
        for name in filenames:
            source_file = current_path / name
            relative_file = source_file.relative_to(source)
            if source_file.is_symlink() or not source_file.is_file():
                continue
            if relative_file.as_posix() in excluded:
                continue
            target = destination / relative_file
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)


def copy_platform_libraries(prefix: Path, output_prefix: Path) -> None:
    library_source = prefix / "lib"
    library_target = output_prefix / "lib"
    library_target.mkdir(parents=True, exist_ok=True)
    for source in sorted(library_source.iterdir()):
        if source.is_file() and not source.is_symlink() and is_dynamic_library(source):
            target_name = linux_soname(source) if sys.platform.startswith("linux") else source.name
            shutil.copy2(source, library_target / target_name)
    if os.name == "nt":
        windows_bin = prefix / "bin"
        if windows_bin.is_dir():
            binary_bin = output_prefix / "bin"
            binary_bin.mkdir(parents=True, exist_ok=True)
            for entry in sorted(windows_bin.iterdir()):
                if entry.is_file() and not entry.is_symlink() and entry.suffix.casefold() == ".dll":
                    shutil.copy2(entry, binary_bin / entry.name)


def linux_soname(path: Path) -> str:
    if not sys.platform.startswith("linux"):
        return path.name
    patchelf = shutil.which("patchelf")
    if not patchelf:
        raise ValueError("Linux engine packaging requires patchelf")
    result = run_checked([patchelf, "--print-soname", str(path)])
    return result or path.name


def locate_plugin_source(prefix: Path) -> Path:
    candidate = prefix / "lib" / "radare2" / ENGINE_VERSION
    if not candidate.is_dir():
        raise ValueError("radare2 install prefix has no versioned plugin directory")
    return candidate.resolve(strict=True)


def locate_sleigh_source(plugin_source: Path, explicit: Path | None) -> Path:
    source = explicit if explicit is not None else plugin_source / "r2ghidra_sleigh"
    resolved = require_source_directory(source, "SLEIGH data")
    if not any(path.is_file() for path in resolved.rglob("*")):
        raise ValueError("SLEIGH data directory contains no regular files")
    return resolved


def copy_runtime(
    prefix: Path,
    plugin_source: Path,
    sleigh_source: Path,
    output_root: Path,
) -> Path:
    output_prefix = output_root / "radare2"
    binary_name = "r2.exe" if os.name == "nt" else "r2"
    binary_target = output_prefix / "bin" / binary_name
    binary_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(resolve_engine_binary(prefix), binary_target)
    copy_platform_libraries(prefix, output_prefix)
    plugin_dir = output_prefix / "plugins"
    copy_tree_files(plugin_source, plugin_dir, frozenset({"r2ghidra_sleigh"}))
    normalize_engine_plugin_assets(plugin_dir)
    strip_macos_debug_symbols(output_root)
    copy_tree_files(prefix / "share" / "radare2", output_prefix / "share" / "radare2")
    copy_tree_files(sleigh_source, output_root / "sleigh")
    return binary_target


def source_library(prefix: Path, plugin_source: Path, name: str) -> Path | None:
    candidates = (
        prefix / "lib" / name,
        plugin_source / name,
        prefix / "bin" / name,
    )
    for candidate in candidates:
        if candidate.exists():
            resolved = candidate.resolve(strict=True)
            if resolved.is_file() and resolved.is_relative_to(prefix):
                return resolved
    return None


def macho_dependencies(image: Path) -> list[str]:
    output = run_checked(["otool", "-L", str(image)])
    return [
        line.strip().split(" (compatibility version", 1)[0]
        for line in output.splitlines()[1:]
        if line.strip()
    ]


def macho_rpaths(image: Path) -> list[str]:
    output = run_checked(["otool", "-l", str(image)])
    paths = re.findall(r"cmd LC_RPATH.*?path (.*?) \(offset [0-9]+\)", output, re.S)
    return [path.strip() for path in paths]


def relocate_macho_image(image: Path, role: str, prefix: Path, plugin_source: Path) -> None:
    changes = []
    for dependency in macho_dependencies(image):
        target = source_library(prefix, plugin_source, Path(dependency).name)
        if target is not None:
            changes.extend(["-change", dependency, f"@rpath/{target.name}"])
    if image.suffix == ".dylib":
        changes.extend(["-id", f"@rpath/{image.name}"])
    for rpath in macho_rpaths(image):
        if os.path.isabs(rpath):
            changes.extend(["-delete_rpath", rpath])
    desired = {
        "binary": "@executable_path/../lib",
        "library": "@loader_path",
        "plugin": "@loader_path/../lib",
    }[role]
    current_rpaths = macho_rpaths(image)
    if role == "plugin" and "@loader_path" not in current_rpaths:
        changes.extend(["-add_rpath", "@loader_path"])
    if desired not in current_rpaths:
        changes.extend(["-add_rpath", desired])
    if changes:
        run_checked(["install_name_tool", *changes, str(image)])
    references = macho_dependencies(image) + macho_rpaths(image)
    if any(os.path.isabs(path) for path in macho_rpaths(image)):
        raise ValueError("Mach-O engine retains an absolute runtime search path")
    if str(prefix) in "\n".join(references):
        raise ValueError("Mach-O engine still references its build prefix")


def relocate_macho(prefix: Path, plugin_source: Path, output_prefix: Path) -> None:
    if not shutil.which("otool") or not shutil.which("install_name_tool"):
        raise ValueError("macOS engine packaging requires otool and install_name_tool")
    images = [(output_prefix / "bin" / "r2", "binary")]
    images.extend((path, "library") for path in (output_prefix / "lib").glob("*.dylib"))
    images.extend((path, "plugin") for path in (output_prefix / "plugins").rglob("*.dylib"))
    for image, role in images:
        relocate_macho_image(image, role, prefix, plugin_source)
        run_checked(["codesign", "--force", "--sign", "-", "--timestamp=none", str(image)])
        run_checked(["codesign", "--verify", "--strict", str(image)])


def linux_library_aliases(prefix: Path, plugin_source: Path) -> dict[str, str]:
    aliases: dict[str, str] = {}
    patchelf = shutil.which("patchelf")
    if not patchelf:
        raise ValueError("Linux engine packaging requires patchelf")
    for directory in (prefix / "lib", plugin_source, prefix / "bin"):
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.exists() and is_dynamic_library(entry):
                resolved = entry.resolve(strict=True)
                if resolved.is_file() and resolved.is_relative_to(prefix):
                    aliases[entry.name] = linux_soname(resolved)
    return aliases


def relocate_elf(prefix: Path, plugin_source: Path, output_prefix: Path) -> None:
    patchelf = shutil.which("patchelf")
    if not patchelf:
        raise ValueError("Linux engine packaging requires patchelf")
    images = [(output_prefix / "bin" / "r2", "$ORIGIN/../lib")]
    images.extend((path, "$ORIGIN") for path in (output_prefix / "lib").iterdir() if is_dynamic_library(path))
    images.extend((path, "$ORIGIN:$ORIGIN/../lib") for path in (output_prefix / "plugins").rglob("*.so*"))
    aliases = linux_library_aliases(prefix, plugin_source)
    for image, rpath in images:
        dependencies = run_checked([patchelf, "--print-needed", str(image)]).splitlines()
        for dependency in dependencies:
            canonical = aliases.get(Path(dependency).name)
            if canonical and canonical != dependency:
                run_checked([patchelf, "--replace-needed", dependency, canonical, str(image)])
        run_checked([patchelf, "--set-rpath", rpath, str(image)])
        dependencies = run_checked([patchelf, "--print-needed", str(image)]).splitlines()
        references = dependencies + [run_checked([patchelf, "--print-rpath", str(image)])]
        if prefix.as_posix() in "\n".join(references):
            raise ValueError("ELF engine still references its build prefix")


def relocate_runtime(prefix: Path, plugin_source: Path, output_prefix: Path) -> None:
    if sys.platform == "darwin":
        relocate_macho(prefix, plugin_source, output_prefix)
    elif sys.platform.startswith("linux"):
        relocate_elf(prefix, plugin_source, output_prefix)


def enforce_bundle_budget(root: Path) -> None:
    files = [path for path in root.rglob("*") if path.is_file()]
    if any(path.is_symlink() or path.stat().st_size == 0 for path in files):
        raise ValueError("engine bundle contains a symlink or empty file")
    if len(files) > MAX_BUNDLE_FILES:
        raise ValueError("engine bundle exceeds the 4,096-file limit")
    if sum(path.stat().st_size for path in files) > MAX_BUNDLE_BYTES:
        raise ValueError("engine bundle exceeds the 100 MiB limit")


def capture_license_inventory(
    binary: Path, output_root: Path, radare2_source: Path, r2ghidra_source: Path
) -> None:
    helper = Path(__file__).with_name("capture_engine_license_inventory.py")
    command = [
        sys.executable,
        str(helper),
        "--radare2",
        str(binary),
        "--radare2-source",
        str(radare2_source),
        "--r2ghidra-source",
        str(r2ghidra_source),
        "--output",
        str(output_root / "radare2-license-inventory.json"),
    ]
    subprocess.run(command, check=True)


def stage_bundle(arguments: argparse.Namespace) -> Path:
    prefix = require_source_directory(arguments.radare2_prefix, "radare2 prefix")
    plugin_source = locate_plugin_source(prefix)
    sleigh_source = locate_sleigh_source(plugin_source, arguments.sleigh_dir)
    parent = arguments.output.resolve().parent
    parent.mkdir(parents=True, exist_ok=True)
    output = arguments.output.resolve()
    if output.exists():
        raise ValueError("engine output directory already exists")
    with tempfile.TemporaryDirectory(prefix="xsec-engine-bundle-", dir=parent) as temporary:
        staged = Path(temporary) / "bundle"
        staged.mkdir()
        binary = copy_runtime(prefix, plugin_source, sleigh_source, staged)
        normalize_build_paths(staged, BuildPathMap(install_prefix=prefix, requested_prefix=arguments.radare2_prefix, radare2_source=arguments.radare2_source, r2ghidra_source=arguments.r2ghidra_source))
        relocate_runtime(prefix, plugin_source, staged / "radare2")
        capture_license_inventory(binary, staged, arguments.radare2_source, arguments.r2ghidra_source)
        enforce_bundle_budget(staged)
        shutil.move(str(staged), output)
    return output
