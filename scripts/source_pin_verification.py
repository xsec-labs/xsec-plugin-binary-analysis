"""Verify pinned source commits and the approved Ghidra patch set."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess


R2_COMMIT = "ad27058877024389292fddf12e1db6e13824ba34"
RADARE2_PATCHSET_SHA256 = "6241d08b3ed5b7bf432d4c3be1ea073b40468737b8a9d486fe4bbfdac7747c2f"
R2GHIDRA_COMMIT = "1b5cba403c4c8751db8434f6790d5e0f132038f4"
GHIDRA_NATIVE_COMMIT = "483ae94bcbc661a77667e52f1eff75928cb6aa2e"
ZLIB_COMMIT = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf"
GHIDRA_NATIVE_PATCHSET_SHA256 = "efde9ac1421a759764737f68a156f7b7aedcffcf81f50d0d7a70542ddd0529b2"
PROCESS_TIMEOUT_SECONDS = 30


def git_text(source: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise ValueError(f"git source verification failed: {source.name}")
    return result.stdout.strip()


def source_tree_changes(source: Path, exclude_sla: bool = False) -> set[str]:
    command = ["git", "-C", str(source), "diff", "--name-only", "-z", "HEAD", "--", "."]
    if exclude_sla:
        command.append(":(exclude)**/*.sla")
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise ValueError(f"git source change scan failed: {source.name}")
    return {path for path in result.stdout.decode("utf-8").split("\0") if path}


def source_diff_sha256(source: Path, exclude_sla: bool = False) -> str:
    command = ["git", "-C", str(source), "diff", "--binary", "HEAD", "--", "."]
    if exclude_sla:
        command.append(":(exclude)**/*.sla")
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=PROCESS_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise ValueError(f"git source patch digest failed: {source.name}")
    return hashlib.sha256(result.stdout).hexdigest()


def verify_source_tree(
    name: str,
    source: Path,
    expected_commit: str,
    allowed_dirty_files: frozenset[str] = frozenset(),
) -> None:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError(f"pinned source path is not a directory: {name}")
    if git_text(source, "rev-parse", "HEAD") != expected_commit:
        raise ValueError(f"source checkout commit does not match the approved pin: {name}")
    if source_tree_changes(source) - allowed_dirty_files:
        raise ValueError(f"pinned source checkout has tracked modifications: {name}")


def verify_patched_radare2(source: Path) -> None:
    source = source.resolve(strict=True)
    if git_text(source, "rev-parse", "HEAD") != R2_COMMIT:
        raise ValueError("radare2 source checkout commit does not match the approved pin")
    expected_files = frozenset({"libr/meson.build", "libr/io/meson.build"})
    if source_tree_changes(source) != expected_files:
        raise ValueError("radare2 source changes do not match the approved patch files")
    if source_diff_sha256(source) != RADARE2_PATCHSET_SHA256:
        raise ValueError("radare2 applied patch set does not match the approved digest")


def verify_patched_ghidra_native(source: Path) -> None:
    source = source.resolve(strict=True)
    if git_text(source, "rev-parse", "HEAD") != GHIDRA_NATIVE_COMMIT:
        raise ValueError("ghidra-native source checkout commit does not match the approved pin")
    compiled_sla = source_tree_changes(source) - source_tree_changes(source, exclude_sla=True)
    if any(not re.fullmatch(r"src/Processors/[^/]+/data/languages/[^/]+\.sla", path) for path in compiled_sla):
        raise ValueError("ghidra-native source has unexpected generated-file changes")
    if source_diff_sha256(source, exclude_sla=True) != GHIDRA_NATIVE_PATCHSET_SHA256:
        raise ValueError("ghidra-native applied patch set does not match the approved digest")


def verify_source_trees(radare2_source: Path, r2ghidra_source: Path) -> None:
    sources = {
        "radare2": radare2_source,
        "r2ghidra": r2ghidra_source,
        "ghidra-native": r2ghidra_source / "subprojects/ghidra-native",
        "zlib": r2ghidra_source / "subprojects/zlib",
    }
    verify_patched_radare2(sources["radare2"])
    verify_source_tree("r2ghidra", sources["r2ghidra"], R2GHIDRA_COMMIT)
    verify_patched_ghidra_native(sources["ghidra-native"])
    verify_source_tree("zlib", sources["zlib"], ZLIB_COMMIT, frozenset({"Makefile", "zconf.h"}))
