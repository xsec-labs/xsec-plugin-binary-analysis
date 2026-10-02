#!/usr/bin/env python3
"""Capture the license inventory reported by a built radare2 runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


from source_pin_verification import (
    GHIDRA_NATIVE_COMMIT,
    GHIDRA_NATIVE_PATCHSET_SHA256,
    R2_COMMIT,
    RADARE2_PATCHSET_SHA256,
    R2GHIDRA_COMMIT,
    ZLIB_COMMIT,
    verify_source_trees,
)

MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_COMPONENTS = 4096
PROCESS_TIMEOUT_SECONDS = 30
LICENSE_ALIASES = {
    "Apache": "Apache-2.0",
    "BSD": "BSD-3-Clause",
    "BSD-3": "BSD-3-Clause",
    "GPL": "GPL-2.0-only",
    "GPL2": "GPL-2.0-only",
    "GPL3": "GPL-3.0-only",
    "LGPL": "LGPL-2.0-only",
    "LGPL2": "LGPL-2.0-only",
    "LGPL3": "LGPL-3.0-only",
    "LGPLv3": "LGPL-3.0-only",
}
PINNED_COMPONENTS = {
    "ghidra-native": "Apache-2.0",
    "zlib": "Zlib",
}

def normalize_license(value: object, component_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"runtime component has no license: {component_name}")
    license_id = value.strip()
    license_id = LICENSE_ALIASES.get(license_id, license_id)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", license_id):
        raise ValueError(f"runtime component has an unmapped license: {component_name}")
    if license_id.upper().startswith("GPL"):
        raise ValueError(f"runtime contains a GPL-licensed component: {component_name}")
    return license_id


def component_record(name: str, metadata: object) -> dict[str, str]:
    if not isinstance(metadata, dict):
        raise ValueError(f"runtime component metadata is invalid: {name}")
    return {"name": name, "license": normalize_license(metadata.get("license"), name)}


def third_party_components(raw: object) -> list[dict[str, str]]:
    if not isinstance(raw, dict):
        raise ValueError("radare2 version report has no thirdparty object")
    return [component_record(f"thirdparty/{name}", metadata) for name, metadata in raw.items()]


def plugin_components(raw: object) -> tuple[list[dict[str, str]], str | None]:
    if not isinstance(raw, dict):
        raise ValueError("radare2 version report has no plugins object")
    components: list[dict[str, str]] = []
    r2ghidra_license = None
    for category, entries in raw.items():
        if not isinstance(entries, list):
            raise ValueError(f"radare2 plugin category is invalid: {category}")
        if category == "crypto":
            validate_crypto_catalog(entries)
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                raise ValueError(f"radare2 plugin record is invalid: {category}")
            name = entry["name"]
            record = component_record(f"plugin/{category}/{name}", entry)
            components.append(record)
            if "ghidra" in name.casefold():
                r2ghidra_license = normalize_license(entry.get("license"), name)
    return components, r2ghidra_license


def validate_crypto_catalog(entries: list[object]) -> None:
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("radare2 crypto catalog contains an invalid record")
        license_id = entry.get("license")
        if license_id is not None:
            normalize_license(license_id, entry["name"])


def inventory_from_report(report: object) -> dict[str, object]:
    if not isinstance(report, dict) or not isinstance(report.get("radare2"), dict):
        raise ValueError("radare2 version report has an invalid root object")
    core_license = normalize_license(report["radare2"].get("license"), "radare2")
    if report["radare2"].get("version") != "6.2.2":
        raise ValueError("radare2 runtime version does not match the approved baseline")
    if core_license != "LGPL-3.0-only":
        raise ValueError("radare2 core license does not match the approved source baseline")
    plugins, r2ghidra_license = plugin_components(report.get("plugins"))
    if r2ghidra_license != "LGPL-3.0-only":
        raise ValueError("built runtime does not report the pinned r2ghidra plugin")
    components = [
        {"name": "radare2", "license": core_license},
        {"name": "r2ghidra", "license": r2ghidra_license},
        *third_party_components(report.get("thirdparty")),
        *plugins,
        *({"name": name, "license": license_id} for name, license_id in PINNED_COMPONENTS.items()),
    ]
    if len(components) > MAX_COMPONENTS:
        raise ValueError("radare2 runtime license inventory exceeds the component limit")
    names = [component["name"].casefold() for component in components]
    if len(names) != len(set(names)):
        raise ValueError("radare2 runtime license inventory contains duplicate component names")
    components.sort(key=lambda component: component["name"].casefold())
    return {"schemaVersion": 1, "radare2Commit": R2_COMMIT, "components": components}


def run_version_report(executable: Path) -> object:
    prefix = executable.parent.parent
    plugin_dir = prefix / "plugins"
    library_paths = [prefix / "bin", prefix / "lib", plugin_dir]
    path_variable = runtime_library_path_variable()
    if not plugin_dir.is_dir():
        raise ValueError("radare2 bundle has no packaged plugin directory")
    with tempfile.TemporaryDirectory(prefix="xsec-r2-license-home-") as home:
        environment = {
            "R2_HOME": home,
            "R2_PREFIX": str(prefix),
            "R2_LIBR_PLUGINS": str(plugin_dir),
            path_variable: os.pathsep.join(str(path) for path in library_paths),
        }
        if os.name == "nt":
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                raise ValueError("Windows SystemRoot is unavailable for engine validation")
            environment["SystemRoot"] = system_root
        result = subprocess.run(
            [str(executable), "-Vj"],
            check=False,
            capture_output=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            env=environment,
        )
    if result.returncode != 0:
        raise ValueError(f"radare2 -Vj failed with exit code {result.returncode}")
    if len(result.stdout) > MAX_REPORT_BYTES:
        raise ValueError("radare2 version report exceeds the 8 MiB limit")
    try:
        return json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"radare2 version report is invalid JSON: {error}") from error


def runtime_library_path_variable() -> str:
    if os.name == "nt":
        return "PATH"
    if sys.platform == "darwin":
        return "DYLD_LIBRARY_PATH"
    if sys.platform.startswith("linux"):
        return "LD_LIBRARY_PATH"
    raise ValueError("binary engine validation does not support this host OS")


def capture_inventory(
    executable: Path,
    output: Path,
    radare2_source: Path,
    r2ghidra_source: Path,
) -> int:
    verify_source_trees(radare2_source, r2ghidra_source)
    executable = executable.resolve(strict=True)
    if not executable.is_file():
        raise ValueError("radare2 executable path is not a regular file")
    inventory = inventory_from_report(run_version_report(executable))
    if output.name != "radare2-license-inventory.json":
        raise ValueError("license inventory output must be radare2-license-inventory.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    inventory_bytes = (json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode("utf-8")
    write_atomic(output, inventory_bytes)
    versions = engine_versions_document(hashlib.sha256(inventory_bytes).hexdigest())
    versions_bytes = (json.dumps(versions, sort_keys=True, indent=2) + "\n").encode("utf-8")
    write_atomic(output.parent / "engine-versions.json", versions_bytes)
    return len(inventory["components"])


def engine_versions_document(inventory_digest: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "radare2": {"version": "6.2.2", "commit": R2_COMMIT, "license": "LGPL-3.0-only"},
        "r2ghidra": {
            "version": "6.2.2",
            "commit": R2GHIDRA_COMMIT,
            "license": "LGPL-3.0-only",
        },
        "dependencies": {
            "ghidra-native": {"commit": GHIDRA_NATIVE_COMMIT, "license": "Apache-2.0"},
            "zlib": {"commit": ZLIB_COMMIT, "license": "Zlib"},
        },
        "radare2PatchSetSha256": RADARE2_PATCHSET_SHA256,
        "ghidraNativePatchSetSha256": GHIDRA_NATIVE_PATCHSET_SHA256,
        "requiredRadare2ConfigureFlags": ["--without-gpl"],
        "licenseInventoryPath": "radare2-license-inventory.json",
        "licenseInventorySha256": inventory_digest,
    }


def write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--radare2", required=True, type=Path)
    parser.add_argument("--radare2-source", required=True, type=Path)
    parser.add_argument("--r2ghidra-source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        component_count = capture_inventory(
            arguments.radare2,
            arguments.output,
            arguments.radare2_source,
            arguments.r2ghidra_source,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        parser.error(str(error))
    print(f"engine_license_inventory.captured components={component_count}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
