#!/usr/bin/env python3
"""Remove the known duplicate from a generated no-GPL plugin list."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re
import stat
import tempfile

EXPECTED_DUPLICATE_TOKENS = frozenset({"arch.sparc_cs"})
ASSIGNMENT = re.compile(r'(?ms)^(STATIC|SHARED)="([^"]*)"$')
PLUGIN_TOKEN = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")


def normalize_plugin_config(text: str) -> tuple[str, tuple[str, ...]]:
    """Keep generated plugin tokens unique while preserving their order."""

    matches = list(ASSIGNMENT.finditer(text))
    names = [match.group(1) for match in matches]
    if sorted(names) != ["SHARED", "STATIC"]:
        raise ValueError("generated plugin config must define STATIC and SHARED once")
    remainder = ASSIGNMENT.sub("", text)
    if remainder.strip():
        raise ValueError("generated plugin config contains unexpected shell text")
    output = text
    removed: list[str] = []
    all_tokens: dict[str, set[str]] = {}
    for match in matches:
        name = match.group(1)
        tokens = match.group(2).split()
        if not tokens or any(not PLUGIN_TOKEN.fullmatch(token) for token in tokens):
            raise ValueError(f"generated {name} plugin list contains an invalid token")
        duplicates = {token for token, count in Counter(tokens).items() if count > 1}
        if duplicates - EXPECTED_DUPLICATE_TOKENS:
            raise ValueError(f"generated {name} plugin list has unreviewed duplicates")
        unique = list(dict.fromkeys(tokens))
        removed.extend(duplicates)
        all_tokens[name] = set(unique)
        replacement = name + '="' + "\n".join(unique) + '"'
        output = output.replace(match.group(0), replacement, 1)
    if all_tokens["STATIC"] & all_tokens["SHARED"]:
        raise ValueError("generated plugin config assigns a plugin as both STATIC and SHARED")
    return output, tuple(sorted(set(removed)))


def plugin_token_sets(text: str) -> dict[str, frozenset[str]]:
    return {
        match.group(1): frozenset(match.group(2).split())
        for match in ASSIGNMENT.finditer(text)
    }


def require_no_gpl_configuration(source: Path) -> Path:
    config = source / "config-user.mk"
    metadata = config.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("radare2 config-user.mk must be a regular file")
    assignments = re.findall(r"^WITH_GPL=(.*)$", config.read_text(encoding="utf-8"), re.M)
    if assignments != ["0"]:
        raise ValueError("radare2 must be configured with WITH_GPL=0")
    return source / "plugins.cfg"


def seed_no_gpl_plugin_config(source: Path) -> tuple[str, ...]:
    """Seed Radare2's documented no-GPL preset before configure runs."""

    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("radare2 source path must be a directory")
    config_path = source / "plugins.cfg"
    try:
        config_path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("radare2 plugins.cfg already exists before preset seeding")

    no_gpl_path = source / "dist" / "plugins-cfg" / "plugins.nogpl.cfg"
    no_gpl_metadata = no_gpl_path.lstat()
    if not stat.S_ISREG(no_gpl_metadata.st_mode):
        raise ValueError("pinned radare2 no-GPL plugin list must be a regular file")
    normalized, removed = normalize_plugin_config(no_gpl_path.read_text(encoding="utf-8"))
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=source, delete=False
    ) as temporary:
        temporary.write(normalized)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(no_gpl_metadata.st_mode & 0o777)
    temporary_path.replace(config_path)
    return removed


def normalize_source_config(source: Path) -> tuple[str, ...]:
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("radare2 source path must be a directory")
    config_path = require_no_gpl_configuration(source)
    no_gpl_path = source / "dist" / "plugins-cfg" / "plugins.nogpl.cfg"
    no_gpl_metadata = no_gpl_path.lstat()
    if not stat.S_ISREG(no_gpl_metadata.st_mode):
        raise ValueError("pinned radare2 no-GPL plugin list must be a regular file")
    metadata = config_path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("generated radare2 plugins.cfg must be a regular file")
    normalized, removed = normalize_plugin_config(config_path.read_text(encoding="utf-8"))
    baseline, _ = normalize_plugin_config(no_gpl_path.read_text(encoding="utf-8"))
    if plugin_token_sets(normalized) != plugin_token_sets(baseline):
        raise ValueError("generated radare2 plugin list differs from the pinned no-GPL list")
    if not removed:
        return removed
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=source, delete=False
    ) as temporary:
        temporary.write(normalized)
        temporary_path = Path(temporary.name)
    temporary_path.chmod(metadata.st_mode & 0o777)
    temporary_path.replace(config_path)
    return removed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="configured radare2 source directory")
    arguments = parser.parse_args()
    removed = normalize_source_config(arguments.source)
    message = ",".join(removed) if removed else "none"
    print(f"radare2 no-GPL plugin duplicates removed: {message}")


if __name__ == "__main__":
    main()
